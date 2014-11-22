(ns cryptopals.core
  (:require [cryptopals.vecutils :as CPVecUtils]
            [cryptopals.prng :as PRNG])
  (:gen-class))

(defn -main
  "I don't do a whole lot ... yet."
  [& args]
  (set! *unchecked-math* true)
  (PRNG/seed-mt19937-mt 4357))
