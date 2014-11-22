(ns cryptopals.set3
  (:use [clojure.java.io]
        [cryptopals.strutils]
        [cryptopals.intutils]
        [cryptopals.vecutils]
        [cryptopals.sequtils]
        [cryptopals.aes]))

(def random-key (random-byte-list 16))
(def iv (vec (random-byte-list 16)))

(def given-strings-b64encoded
  ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc="
   "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic="
   "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw=="
   "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg=="
   "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl"
   "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA=="
   "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw=="
   "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8="
   "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g="
   "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"])

(def given-strings
  (vec 
   (map #(base64-decode %)
        given-strings-b64encoded)))

(def crypted-data-vec
  (vec 
   (map #(aes-cbc-encrypt % random-key iv)
        given-strings)))

(def first-string-block
  (first (partition 16 (first given-strings))))

(defn padding-oracle
  [cr-data]
  (try
    (aes-cbc-decrypt cr-data random-key iv)
    true
    (catch javax.crypto.BadPaddingException ex
      false)))

(def zero16 (vec (repeated -128 16)))
(def sixteen16 (vec (repeated 16 16)))

(defn n-padding
  [guess-block enc-block]
  (one-that-fits (fn [b]
                   (let [next-byte (inc (get guess-block b))
                         mod-guess-block (assoc guess-block b next-byte)]
                     (not (padding-oracle (concat mod-guess-block enc-block)))))
                   (range 16)))

(defn byte-guess
  [guess-block idx block]
  (one-that-fits #(padding-oracle (concat (assoc guess-block idx %) block))
                 (byte-range)))

(defn inc-padding-block
  [pad-block idx]
  (let [cur-pad (- 16 idx)
        next-pad (inc cur-pad)]
    (loop [pad-block pad-block
           idx idx]
      (if (= idx 16)
        pad-block
        (let [pad-byte (get pad-block idx)
              plain-text-byte (bit-xor pad-byte cur-pad)
              inc-pad-byte (bit-xor plain-text-byte next-pad)]
          (recur (assoc pad-block idx inc-pad-byte)
                 (inc idx)))))))

(defn decrypt-block
  [block]
  (let [lucky-byte (byte-guess zero16 15 block)
        valid-padding (assoc zero16 15 lucky-byte)
        msg-len (n-padding valid-padding block)]
    (loop [idx (dec msg-len)
           valid-padding valid-padding]
      (if (= -1 idx)
        (vec-xor-vec valid-padding sixteen16)
        (let [next-valid-padding (inc-padding-block valid-padding (inc idx))
              lucky-byte (byte-guess next-valid-padding idx block)]
          (recur (dec idx)
                 (assoc next-valid-padding idx lucky-byte)))))))

(defn challenge-17
  []
  (doseq [cr-line crypted-data-vec]
    (println (vec->str (flatten (map (fn [x y]
                                       (vec-xor-vec (vec y) (decrypt-block x)))
                                     (partition 16 cr-line)
                                     (partition 16 (concat iv cr-line))))))))

(def nonce [0 0 0 0 0 0 0 0])
(def ch-17-data (base64-decode "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=="))
(def ch-17-pass (.getBytes "YELLOW SUBMARINE" "US-ASCII"))

(defn challenge-18
  []
  (println (vec->str (aes-ctr-crypt ch-17-data ch-17-pass nonce))))

(def ch-19-path "/Users/myeyesareblind/Documents/ch-19.txt")
(def ch-19-plain-data (map #(base64-decode %) (.split #"\n" (slurp ch-19-path))))
(def ch-19-data (map #(aes-ctr-crypt % ch-17-pass nonce) ch-19-plain-data))

(defn bytes-guess
  [lhs rhs]
  (->>
   (loop [lhs lhs
          rhs rhs
          rs []]
     (if (or (empty? lhs)
             (empty? rhs))
       rs
       (recur (rest lhs)
              (rest rhs)
              (conj rs (possible-bytes (bit-xor (first lhs) (first rhs)))))))
   (map (fn [s]
          (filter #(every? symbol-byte? %) s)))))


(defn contains-at-least-one?
  [one-set list-set]
  (some #(not (empty? (clojure.set/intersection one-set %))) list-set))

(defn filter-similar-list
  [lhs-list rhs-list]
  (loop [lhs-list lhs-list
         rhs-list rhs-list
         rs []]
    (if (or (empty? lhs-list)
            (empty? rhs-list))
      rs
      (do
        (let [filtered-list (filter (fn [x]
                                      (contains-at-least-one? x (first rhs-list)))
                                    (first lhs-list))]
          (recur (rest lhs-list)
                 (rest rhs-list)
                 (conj rs filtered-list)))))))

(defn possible-print
  [alist]
  (doseq [sub-list alist]
          (print "_")
          (doseq [actual-set sub-list]
            (doseq [symb actual-set]
              (print (String. (byte-array [symb]) "US-ASCII"))))))

(defn challenge-19
  []
  (let [lhs-row (first ch-19-data)
        possible-xor (loop [rhs-row (rest ch-19-data)
                            rs []]
                       (if (empty? rhs-row)
                         rs
                         (recur (rest rhs-row)
                                (conj rs (bytes-guess lhs-row (first rhs-row))))))]
    (possible-print (reduce #(filter-similar-list %1 %2) possible-xor))))

(def cc-data [118 -47 -53 75 -81 -94 70 -30 -29 -81 3 93])

(def ch-20-path "/Users/myeyesareblind/Downloads/20.txt")
(def ch-20-plain-data (map #(base64-decode %) (.split #"\n" (slurp ch-20-path))))
(def ch-20-data (map #(aes-ctr-crypt % ch-17-pass nonce) ch-20-plain-data))

(defn challenge-20
  []
  (let [min-len (reduce min (map #(count %) ch-20-data))
        column-data (for [i (range min-len)]
                      (map #(nth % i) ch-20-data))
        key-column (map #(detect-single-char-xor %) column-data)]
    (doseq [col ch-20-data]
      (println (vec->str (vec-xor-vec col key-column))))))
