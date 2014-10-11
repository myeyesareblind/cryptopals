(ns cryptopals.set1
  (:use [clojure.java.io])
  (:require [cryptopals.strutils :as svu]
            [cryptopals.vecutils :as vu]
            [cryptopals.sequtils :as sequ]))

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

(def challenge-5
  []
  (let [s "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"
        k "ICE"
        v-s (svu/str->vec s)
        v-k (svu/str->vec k)]
    (println (svu/vec->hex-str (vu/vec-xor-vec v-s v-k))))

 (let [s1 "this is a test"
       s2 "wokka wokka!!!"
       v1 (svu/str->vec s1)
       v2 (svu/str->vec s2)]
   (vu/vec-hamm-dist v1 v2))
 
(svu/base64-decode (svu/base64-encode "sfdkjhkjhsafdafskjh"))
 
(defn challenge-6
  []
  (let [enc-data (svu/str->vec (svu/base64-decode (slurp "/Users/myeyesareblind/Downloads/6.txt")))]
    (let [map-klen-hamm-dist (reduce #(assoc %1 %2 (vu/count-aprox-hamm-dist enc-data %2)) {} (range 2 41))
          mins (cryptopals.sequtils/min-vals-in-map map-klen-hamm-dist 5)]
      (println mins)
      (let [decrypt-variants (for [klen mins]
                               (let [sub-vecs (sequ/sub-vectors-with-key-len enc-data klen)
                                     keys (vec (for [v sub-vecs] (detect-single-char-xor v)))
                                     dec-vec (vu/vec-xor-vec enc-data keys)]
                                 {:original dec-vec, :score (svu/vec-score dec-vec)}))]
        (let [best-decrypt (reduce #(if (> (%1 :original)
                                                (%2 :original))
                                                %1 %2) decrypt-variants)]
          (println (svu/vec->str (best-decrypt :original)))))))
          
                     

        
(defn       

;  (:import java.io.File)
;  (:require [clojure.java.io :as io]
;            [ez-image.core :as ez-image]
;            [me.raynes.fs :as fs])
;  (:import [java.io File]
;           [javax.imageio ImageIO]))
