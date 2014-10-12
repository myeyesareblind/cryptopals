(ns cryptopals.strutils
  (:import [org.apache.commons.codec.binary Base64]
           [org.apache.commons.codec.binary StringUtils]))

(defn hex-str->vec
  [hex-str]
  (vec 
   (for [[x y] (partition 2 hex-str)]
     (Integer/parseInt (str x y) 16))))

(defn vec->hex-str
  [byte-vec]
  (apply str
         (map #(format "%02x" (int %)) byte-vec)))

(defn vec->str
  [v]
  (apply str (map char v))) 

(defn str->vec
  [s]
  (vec (for [c s]
         (int c))))

(defn base64-decode
  [s]
  (StringUtils/newStringUtf8 (Base64/decodeBase64 s)))

(defn base64-encode
  [s]
  (Base64/encodeBase64String (StringUtils/getBytesUtf8 s)))

(defn vec-score
  [v]
  (count (filter #(or
                   (and (> % 0x30) (< % 0x39))
                   (and (> % 0x41) (< % 0x5a))
                   (and (> % 0x61) (< % 0x7a))
                   (= % 0x20))
                 v)))
