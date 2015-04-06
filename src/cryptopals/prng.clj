(ns cryptopals.prng
  (:use [clojure.pprint]))

(def N 624)
(def M 397)
(def MATRIX_A 0x9908b0df)
(def UPPER_MASK 0x80000000)
(def LOWER_MASK 0x7fffffff)

(defn print-as-binary
  [y]
  (cl-format true "~64'0',B~%" y))

(defn tempering-a
  [y]
  (bit-xor y (bit-shift-right y 11)))

(defn tempering-b
  [y]
  (bit-xor y (bit-and (bit-shift-left y 7) 0x9d2c5680)))

(defn tempering-c
  [y]
  (bit-xor y (bit-and (bit-shift-left y 15) 0xefc60000)))

(defn tempering-d
  [y]
  (bit-xor y (bit-shift-right y 18)))

(defn bit-in-range
  [rng]
  (loop [rs 0 rng rng]
    (if (empty? rng)
      rs
      (recur (+ rs (bit-shift-left 1 (first rng)))
             (rest rng)))))

(defn bit-at-index
  [x idx]
  (bit-and (bit-in-range (list idx)) x))

(defn un-tempering-a
  [y]
  (loop [rs 0
         idx 63]
    (if (= -1 idx)
      rs
      (if (>= idx 52)
        (recur (bit-or rs (bit-at-index y idx)) (dec idx))
        (recur (bit-or rs (bit-xor 
                           (bit-at-index y idx)
                           (bit-at-index (bit-shift-right rs 11) idx))) (dec idx))))))

(defn un-tempering-b
  [y]
  (loop [rs 0
         idx 0]
    (if (= 64 idx)
      rs
      (if (< idx 7)
        (recur (bit-or rs (bit-at-index y idx)) (inc idx))
        (recur (bit-or rs (bit-xor
                           (bit-at-index y idx)
                           (bit-and (bit-at-index (bit-shift-left rs 7) idx)
                                    0x9d2c5680))) (inc idx))))))
  

(defn un-tempering-c
  [y]
  (loop [rs 0
         idx 0]
    (if (= 64 idx)
      rs
      (if (< idx 15)
        (recur (bit-or rs (bit-at-index y idx)) (inc idx))
        (recur (bit-or rs (bit-xor
                           (bit-at-index y idx)
                           (bit-and (bit-at-index (bit-shift-left rs 15) idx)
                                    0xefc60000))) (inc idx))))))

(defn un-tempering-d
  [y]
  (loop [rs 0
         idx 63]
    (if (= -1 idx)
      rs
      (if (>= idx 45)
        (recur (bit-or rs (bit-at-index y idx)) (dec idx))
        (recur (bit-or rs (bit-xor 
                           (bit-at-index y idx)
                           (bit-at-index (bit-shift-right rs 18) idx))) (dec idx))))))

(defstruct mt19937-prng :mt :mti :seed)

(defn new-mt19937-prng
  []
  (struct mt19937-prng [] N 4357))

(defn- print-state
  [v]
  (dotimes [i (count v)]
    (cl-format true "~3D  ~10D~%" i (get v i))))

(defn- mt19937-init-state-vector
  ; return state vector
  [seed]
  (loop [mt (transient []) 
         i 0
         seed seed]
    (if (= i N)
      (persistent! mt)
      (let [mti (bit-and seed 0xffff0000)
            next-seed (inc (* 69069 (long seed)))]
        (recur (conj! mt (bit-or mti (bit-shift-right (bit-and next-seed 0xffff0000) 16)))
               (inc i)
               (inc (* (long next-seed) 69069)))))))

(defn- mt19937-gen-numbers
  [seed]
  (loop [mt (transient (mt19937-init-state-vector seed))
         kk 0]
    (if (= kk N)
      (persistent! mt)
      (let [idx (cond
                 (< kk (- N M)) (+ kk M)
                 (< kk (dec N)) (+ kk (- M N))
                 (= kk (dec N)) (dec M))
            y (bit-or 
               (bit-and (get mt kk) UPPER_MASK)
               (bit-and (get mt (if (= (inc kk) N) 0 (inc kk))) LOWER_MASK))]
        (recur (assoc! mt kk 
                       (-> 
                        (get mt idx)
                        (bit-xor (bit-shift-right y 1))
                        (bit-xor (if (= 1 (bit-and y 1)) MATRIX_A 0))))
               (inc kk))))))

(defn- get-rand
  [mt-struct]
  (let [mt-struct (if (= (:mti mt-struct) N)
                    (assoc mt-struct 
                      :mt (mt19937-gen-numbers (:seed mt-struct))
                      :mti 0)
                    mt-struct)]
    (let [y (->
             (get (:mt mt-struct)
                  (:mti mt-struct))
             (tempering-a)
             (tempering-b)
             (tempering-c)
             (tempering-d))]
      (list (assoc mt-struct :mti (inc (:mti mt-struct)))
            y))))

(defn genrand
  [seed n]
  (loop [mt-struct (struct mt19937-prng (mt19937-gen-numbers seed) 0 seed)
         rs (transient [])
         n n]
    (if (zero? n)
      (persistent! rs)
      (let [[next-mt-struct rnd] (get-rand mt-struct)]
        (recur next-mt-struct
               (conj! rs rnd)
               (dec n))))))

(defn hack-genrand
  [prng-list]
  
