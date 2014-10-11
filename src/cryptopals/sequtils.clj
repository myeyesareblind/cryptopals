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
