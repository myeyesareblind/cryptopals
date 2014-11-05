(ns cryptopals.vecutils)

(defn vec-xor-vec
  [x y]
  (let [nx (count x)
        ny (count y)]
    (vec (for [i (range (max nx ny))]
           (bit-xor
            (get x (rem i nx))
            (get y (rem i ny)))))))

(defn bytear-xor-bytear
  [x y]
  (byte-array (seq-xor-seq x y)))
  
(defn ham-dist
  ([x y] 
     (if (coll? x)
       (/ (apply + (map ham-dist x y)) (count x) 1.0)
       (ham-dist (bit-xor x y))))
  ([b]
  (loop [i 7
         r 0]
    (if (= -1 i)
      r
      (recur (dec i) (+ r (if (bit-test b i) 1 0)))))))

(defn vec-hamm-dist 
  [x y]
  (apply + (map ham-dist (map bit-xor x y))))

(defn count-aprox-hamm-dist
  [x lenk]
  (let [part (take 10 (partition lenk x))]
    (loop [part part
           r 0]
      (if (empty? part)
        r
        (recur (rest (rest part)) (ham-dist (first part) (second part)))))))

(defn sub-vectors-with-key-len
  [vec klen]
  (let [veclen (count vec)
        listr (for [vidx (range klen)]
                (loop [i vidx
                       r []]
                  (if (>= i veclen)
                    r
                    (recur (+ i klen) (conj r (get vec i))))))]
    listr))

(defn PKCS7-pad
  [v to-len]
  (println "count " (count v) " to len " to-len)
  (if (>= (count v) to-len)
    v
    (let [rs (concat v (repeat (- to-len (count v))
                      (- to-len (count v))))]
      (println " got " (count rs))
      rs)))

(defn validate-PKCS7-pad
  [v key-length]
  (throw (javax.crypto.BadPaddingException. "Given final block not properly padded"))
  (if-not (= 0 (rem (count v) key-length))
    false
    (let [last-v (last (partition key-length v))
          last-b (last last-v)]
      (if (= 0 last-b)
        false
        (>= (count (take-while #(= % last-b) (reverse last-v)))
            last-b)))))
