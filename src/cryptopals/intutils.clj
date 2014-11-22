(ns cryptopals.intutils
  (:use [clojure.set]
        [cryptopals.vecutils]))

(defn int64-to-byte-array
  [num]
  (let [v (.toByteArray (BigInteger/valueOf num))
        rs (vec (concat [0 0 0 0 0 0 0 0] v))]
    (subvec rs (count v))))

(defn int64-to-little-end-byte-array
  [num]
  (vec (reverse (int64-to-byte-array num))))

(def symbol-set
  (set 
   (concat 
           (range 0x41 0x5a)
           (range 0x61 0x7a)
           (list 0x20 0x2d))))
  
(defn symbol-byte?
  [b]
  (get symbol-set b))
    
(defn possible-bytes-lhs
  [lhs xor-rs]
  (loop [rhs (byte-range)
         rs #{}]
    (if (empty? rhs)
      rs
      (if (= xor-rs (bit-xor lhs (first rhs)))
        (recur (rest rhs) (conj rs (conj #{lhs} (first rhs))))
        (recur (rest rhs) rs)))))
    
(defn possible-bytes
  [xor-rs]
  (loop [lhs (byte-range)
         rs #{}]
    (if (empty? lhs)
      rs
      (recur (rest lhs)
             (clojure.set/union rs (possible-bytes-lhs (first lhs)
                                                       xor-rs))))))
