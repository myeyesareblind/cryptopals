(ns cryptopals.set2
  (:use [clojure.java.io]
        [cryptopals.strutils]
        [cryptopals.vecutils]
        [cryptopals.sequtils]
        [cryptopals.aes]))

(defn challenge-10
  []
  (let [enc-data (vec (base64-decode (slurp "/Users/myeyesareblind/Downloads/10.txt")))]
    (let [dec-data (aes-cbc-decrypt enc-data (repeat 16 0) (str->vec "YELLOW SUBMARINE"))]
      (let [re-enc-data (aes-cbc-encrypt dec-data
                                         (repeat 16 0)
                                         (str->vec "YELLOW SUBMARINE"))]
        (= enc-data re-enc-data)))))

(defn challenge-11
  []
  (let [enc-data (aes-random-encrypt 
                  (vec (.getBytes (slurp "/Users/myeyesareblind/Downloads/pleasure.txt"))))]
    (if (zero? (number-of-duplicate-blocks enc-data key-length))
      (println "cbc")
      (println "ecb"))))


(def secret-data 
  (base64-decode "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"))

(def random-key (random-byte-list 16))
(def iv (vec (random-byte-list 16)))
(def random-prefix (random-byte-list 2))

(defn oracle-encrypt
  [data]
  (aes-ecb-encrypt data random-key))

(defn decrypt-byte
  [seq encoded-seq]
  (loop [rng (range -128 128)]
    (if (= encoded-seq (oracle-encrypt (conj seq (first rng))))
      (first rng)
      (recur (rest rng)))))

(defn challenge-12
  []
  (println (loop [decode-seq (str->vec "AAAAAAAAAAAAAAA") ;15xA
                  encoded secret-data
                  decoded []]
             (if (empty? encoded)
               (vec->str decoded)
               (let [dec-byte (->>
                               (conj decode-seq (first encoded))
                               (oracle-encrypt)
                               (decrypt-byte decode-seq))]
                 (recur (subvec (conj decode-seq dec-byte) 1 16)
                        (rest encoded)
                        (conj decoded dec-byte)))))))

(defn profile-for
  [email]
  (aes-ecb-encrypt 
   (.getBytes (kvencode (list (list "email" email)
                              '("uid" 10) 
                              '("role" "user")))
              "US-ASCII")
   random-key))

(defn decrypt-profile-for
  [crypto-data]
  (let [dec (aes-ecb-decrypt crypto-data random-key)
        s (String. (byte-array dec))]
    (kvdecode s)))

(defn challenge-13
  []
  (let [tricky-email (str "AAAAAAAAAAadmin" 
                          (String. (byte-array (repeatedly 11 (fn [] 11)))))
        crypto-profile (profile-for tricky-email)
        admin-byte-seq (second (partition 16 crypto-profile))
        hack-profile (profile-for "aaaaa@bar.com")]
    (let [no-admin-hack (subvec hack-profile 0 (- (count hack-profile) 16))
          with-admn-hack (flatten (conj no-admin-hack admin-byte-seq))]
      (println (decrypt-profile-for with-admn-hack)))))


(defn oracle-encrypt-hard
  [data]
  (aes-ecb-encrypt (concat random-prefix data secret-data) random-key))

(defn decrypt-byte-hard
  [sample enc-data take-idx]
  (loop [rng (range -128 128)]
    (if (empty? rng)
      nil
      (if (= enc-data (take take-idx (oracle-encrypt-hard (conj sample (first rng)))))
        (first rng)
        (recur (rest rng))))))

(defn challenge-14
  []
  (let [sample (loop [iter-sample (repeatedly (* 25 key-length) (fn [] 0))]
                 (if (= 25 (number-of-duplicate-blocks (oracle-encrypt-hard iter-sample) key-length))
                   iter-sample
                   (recur (conj iter-sample 0))))]

    (let [enc-sample (oracle-encrypt-hard sample)
          dup-block (duplicate-block-in-seq enc-sample key-length)
          enc-part-sample (partition key-length enc-sample)
          idx (last (keep-indexed (fn [i v] (when (= dup-block v) i)) enc-part-sample))
          take-idx (* key-length (+ 1 idx))]

      (loop [sample (vec (rest sample))
             sec-data (flatten (drop (+ 1 idx) enc-part-sample))
             res []]
        (if (empty? sec-data)
          (vec->str res)
          (let [dec-byte (decrypt-byte-hard (vec (concat sample res))
                                            (take take-idx (oracle-encrypt-hard sample))
                                            take-idx)]
            (if (nil? dec-byte)
              (vec->str res)
              (recur (vec (rest sample))
                     (rest sec-data)
                     (conj res dec-byte)))))))))

(def prepend-str "comment1=cooking%20MCs;userdata=")
(def append-str ";comment2=%20like%20a%20pound%20of%20bacon")
(def hack-str ";admin=true;AAAA")
(def zero48 (repeated 0 48))
(def zero16 (repeated 0 16))

(defn encrypt-query
  [userdata]
  (aes-cbc-encrypt (concat (str->vec prepend-str)
                           userdata
                           (str->vec append-str)) 
                   random-key
                   iv))

(defn decrypt-query
  [vec-query]
  (vec->str (aes-cbc-decrypt vec-query random-key iv)))

(defn r-partition
  [col n]
  (partition n col))

(defn challenge-16
  []
  (let [zero-enc (encrypt-query zero48)
        prev-enc-block (vec (nth (partition 16 zero-enc) 2))
        cur-enc-block (vec (nth (partition 16 zero-enc) 3))
        before-xor (vec-xor-vec prev-enc-block zero16)
        xor-block (vec-xor-vec before-xor (str->vec hack-str))]
    (let [dec (flatten (concat (first (split-at 32 zero-enc))
                               xor-block
                               cur-enc-block
                               (rest (split-at 64 zero-enc))))
          dec-str (decrypt-query dec)]
      (re-find (re-pattern ";admin=true;") dec-str))))

