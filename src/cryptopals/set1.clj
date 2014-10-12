(ns cryptopals.set1
  (:use [clojure.java.io])
  (:require [cryptopals.strutils :as svu]
            [cryptopals.vecutils :as vu]
            [cryptopals.sequtils :as sequ]
            [cryptopals.aes :as aes]))

(defn detect-single-char-xor
  [v]
    (let [best-key (reduce (fn [x y]
              (if (> (svu/vec-score (map #(bit-xor x %) v))
                     (svu/vec-score (map #(bit-xor y %) v)))
                x
                y))
            (range 0xff))]
      best-key))

(defn challenge-4
  []
  (with-open [rdr (reader "/Users/myeyesareblind/Downloads/4.txt")]
    (def best [])
    (doseq [line (line-seq rdr)]
      (when (> (svu/vec-score (detect-single-char-xor line))
               (svu/vec-score (detect-single-char-xor best)))
        (def best line)))
    (svu/vec->str (detect-single-char-xor best))))

(defn challenge-5
  []
  (let [s "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"
        k "ICE"
        v-s (svu/str->vec s)
        v-k (svu/str->vec k)]
    (println (svu/vec->hex-str (vu/vec-xor-vec v-s v-k)))))

(defn challenge-6
  []
  (let [enc-data (svu/base64-decode (slurp "/Users/myeyesareblind/Downloads/6.txt"))]
    (let [map-klen-hamm-dist (reduce #(assoc %1 %2 (vu/count-aprox-hamm-dist enc-data %2)) {} (range 2 41))
          mins (cryptopals.sequtils/min-vals-in-map map-klen-hamm-dist 5)]
      (println mins)
      (let [decrypt-variants (for [klen mins]
                               (let [sub-vecs (sequ/sub-vectors-with-key-len enc-data klen)
                                     keys (vec (for [v sub-vecs] (detect-single-char-xor v)))
                                     dec-vec (vu/vec-xor-vec enc-data keys)]
                                 dec-vec))]
        (let [best-decrypt (reduce #(if (> (svu/vec-score %1)
                                           (svu/vec-score %2))
                                      %1 %2) decrypt-variants)]
          (println (svu/vec->str best-decrypt)))))))

(defn challenge-7
  []
  (let [enc-data (svu/base64-decode (slurp "/Users/myeyesareblind/Downloads/7.txt"))]
    (println (vec enc-data))
    (println (svu/vec->str (aes/aes-decrypt enc-data (.getBytes "YELLOW SUBMARINE" "US-ASCII") "AES/ECB/PKCS5Padding")))))


(defn challenge-8
  []
  (let [s (slurp "/Users/myeyesareblind/Downloads/8.txt")
        linexs (vec (.split s "\n"))
        line-bytexs (for [line linexs]
                      (svu/hex-str->vec line))]
    (let [list-n-occurances 
          (for [line-byte line-bytexs]
            (let [sub-line-bytes (partition-all 16 line-byte)]
              (loop [sub-line-bytes sub-line-bytes
                     r {}]
                (if (empty? sub-line-bytes)
                  (reduce #(if (> (second %1) (second %2)) %1 %2) r)
                  (let [line (first sub-line-bytes)]
                    (recur (rest sub-line-bytes)
                           (assoc r line (if (r line)
                                           (inc (r line))
                                           1))))))))]
      (println (svu/vec->hex-str (first (reduce (fn [m1 m2]
                         (if (> (second m1) (second m2)) m1 m2)) list-n-occurances)))))))
