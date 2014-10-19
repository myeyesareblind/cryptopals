(ns cryptopals.set1
  (:use [clojure.java.io]
        [cryptopals.strutils]
        [cryptopals.vecutils]
        [cryptopals.sequtils]
        [cryptopals.aes]))

(defn challenge-10
  []
  (let [enc-data (vec (base64-decode (slurp "/Users/myeyesareblind/Downloads/10.txt")))]
    (let [dec-data (aes-crypto-cbc-decrypt enc-data (repeat 16 0) (str->vec "YELLOW SUBMARINE"))]
      (let [re-enc-data (aes-crypto-cbc-encrypt dec-data
                                                (repeat 16 0)
                                                (str->vec "YELLOW SUBMARINE"))]
        (= enc-data re-enc-data)))))
