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
