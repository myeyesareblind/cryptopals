(ns cryptopals.sequtils)

(defn min-vals-in-map
  [m ntimes]
  (loop [m m
         ntimes ntimes
         rs []]
    (if (= 0 ntimes)
      rs
      (let [[min-key min-val] (reduce (fn [[lhs-k lhs-v]
                                         [rhs-k rhs-v]]
                                      (if (< lhs-v rhs-v)
                                        [lhs-k lhs-v]
                                        [rhs-k rhs-v])) m)]
        (recur (dissoc m min-key) (dec ntimes) (conj rs min-key))))))


(defn number-of-duplicate-blocks
  [inseq szblock]
  (loop [seq inseq
         res 0
         i 0]
    (if (or (= i szblock)
            (empty? seq))
      res
      (recur (rest seq)
             (max 
              (->> (partition szblock seq)
                   (reduce (fn [hash x]
                             (assoc hash x (if (hash x) (inc (hash x)) 1))) {})
                   (reduce (fn [acc [k v]] (+ acc (if (> v 1) v 0))) 0))
              res)
             (inc i)))))

(defn random-list
  [nelements min max]
  (doall (repeatedly nelements #(- (rand-int (+ (Math/abs min) (Math/abs max)))
                                   (Math/abs min)))))

(defn random-byte-list
  [nelements]
  (random-list nelements -128 128))
