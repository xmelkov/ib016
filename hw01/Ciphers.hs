{- | First assignment for IB016, semester spring 2017, 20 points (+bonus).

== Task overview

Your task is to implement several simple encryption/decryption routines.

  * Monoalphabetic substitution cipher, for general description see the
    [Wikipedia page on substitution cipher](http://en.wikipedia.org/wiki/Substitution_cipher).
  * Caesar shift cipher, for general description see the
    [Wikipedia page on Caesar cipher](http://en.wikipedia.org/wiki/Caesar_cipher).
  * Polyalphabetic substitution encryption called Vigenere cipher, for general description see
    [Wikipedia page on Vigenere cipher](http://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher).

The ciphers you should implement differ slightly from their historical
prototypes. Namely, they work only on lower-case English letters and ignore
other characters, letters are numbered @0..25@. Please make sure to adhere to
the specification provided below.

== Tips and tricks

  * You may find several useful functions in
  [Prelude](https://hackage.haskell.org/package/base-4.8.2.0/docs/Prelude.html),
  [Data.List](https://hackage.haskell.org/package/base-4.8.2.0/docs/Data-List.html),
  [Data.Char](https://hackage.haskell.org/package/base-4.8.2.0/docs/Data-Char.html) and
  [Data.Tuple](https://hackage.haskell.org/package/base-4.8.2.0/docs/Data-Tuple.html).
  * The 'mod' function does not guarantee a positive result.

== Module and package constraints

You can use any modules from the
<https://hackage.haskell.org/package/base-4.8.2.0/ base> package if you wish.
However, try not to use list indexing, i.e. do not use the function '!!'.  If
you wish so, you can also use Unicode syntax from
<https://hackage.haskell.org/package/unicode-prelude-0.1.1 unicode-prelude> but
no other packages are allowed.
-}

-- Name: Name Surname
-- UID: 123456

module Ciphers (
    -- * Monoaplhabetic substitution cipher (4 points)
      encryptSubstitution
    , decryptSubstitution
    -- * Caesar cipher (3 points)
    , encryptCaesar
    , decryptCaesar
    -- * Vigenere cipher (4 points)
    , encryptVigenere
    , decryptVigenere
    -- * Using multiple ciphers (3 points)
    , applyMultiple
    -- * Cryptanalysis assistant (6+ points)
    , assistant
) where

import Data.Char
import Data.List
import Data.Function

-- | Encrypt the given plaintext using monoaplhabetic substitution according to
-- the permutation given in the for of associative list. In this case the range
-- of characters is not limited (any value of 'Char' type can map to any value
-- of 'Char' type).
--
-- The first argument is a list of 'Char' tuples representing the permutation.
-- The encryption process works on each character of the plaintext independently
-- in the following way:
--
--   * If the list contains @(x, y)@ then @x@ is encrypted as @y@.
--   * If there is no tuple with @x@ as the first component, @x@ is encrypted as @x@.
--
-- The valid permutation is defined as follows:
--
--  * If the list contains @(x, y)@, then it contains @(y, z)@.
--  * If the list contains @(x, z)@ and @(y, z)@, then @x == y@.
--  * If the list contains @(x, y)@ and @(x, z)@, then @y == z@.
--  * The list does not contain any element multiple times.
--  * The set of characters in the first components is the same as
--    in the second components of the tuples.
--
-- If the first argument is not a permutation the function should fail
-- with an appropriate error message.
--
-- >>> encryptSubstitution [('a', 'b'), ('b', 'c'), ('c', 'a')] "abcde"
-- "bcade"
--
-- >>> encryptSubstitution [('a', 'b'), ('b', 'c'), ('c', 'd')] "abcde"
-- *** Exception: Not a permutation.
--
-- >>> encryptSubstitution [] "abcde"
-- "abcde"

isValidSubstitution :: [(Char,Char)] -> Bool
isValidSubstitution permutation = let sortedDomain = (sort . fst . unzip) permutation
                                      sortedImage = (sort . snd . unzip) permutation
                                  in all id [(==) sortedDomain sortedImage, not (any id $ zipWith (==) sortedDomain $ tail sortedDomain)]

encryptSubstitution :: [(Char, Char)] -- ^ Character permutation
                    -> String         -- ^ Plaintext
                    -> String         -- ^ Ciphertext
encryptSubstitution permutation plaintext = if isValidSubstitution permutation then map (\c -> maybe c id $ lookup c permutation) plaintext
                                                                               else error "Provided substitution is not a permutation"

-- | Decrypt the given plaintext using monoaplhabetic substitution.
-- For detailed specification, see 'encryptSubstitution'.
--
-- For every valid permutation @p@ and for every String @s@ it should
-- hold that @decryptSubstitution p (encryptSubstitution p s) == s@.
--
-- >>> decryptSubstitution [('a', 'b'), ('b', 'c'), ('c', 'a')] "bcade"
-- "abcde"
--
-- >>> decryptSubstitution [('a', 'b'), ('b', 'c'), ('c', 'd')] "bcade"
-- *** Exception: Not a permutation.
decryptSubstitution :: [(Char, Char)] -- ^ Character permutation
                    -> String         -- ^ Ciphertext
                    -> String         -- ^ Plaintext
decryptSubstitution permutation = encryptSubstitution (map (\(a,b) -> (b,a)) $ permutation)

-- | Shifts each input character by adding given shift value (modulo 26). This
-- works only on English lowercase letters. That is, if @'a'@ is shifted by 3,
-- it is changed to @'d'@, @'z'@ shifted by 3 is @'c'@.
--
-- When shifting (modulo 26) you can make use of function
-- [fromEnum](http://hackage.haskell.org/packages/archive/base/latest/doc/html/Prelude.html#v:fromEnum)
-- which converts any 'Enum' values (including 'Char') to number. There is also
-- 'toEnum' function defined in the same
-- [typeclass](http://hackage.haskell.org/packages/archive/base/latest/doc/html/Prelude.html#t:Enum).
--
-- The shift must be positive number, but it need not be less then 26.
--
-- >>> encryptCaesar 5 "abc"
-- "fgh"
--
-- >>> encryptCaesar (-3) "abc"
-- *** Exception: Incorrect shift.

validCaesarLetter :: Char -> Bool
validCaesarLetter = (&&) <$> isAlpha <*> isLower

normalizeLetter :: Char -> Int
normalizeLetter = (flip (-) (fromEnum 'a')) . fromEnum

shiftLetter :: Int -> Char -> Char
shiftLetter shift c = if (validCaesarLetter c) then ((toEnum) . ((+) (fromEnum 'a')) . (`rem` 26) . ((+) shift) . normalizeLetter) c
                                               else c

encryptCaesar :: Int    -- ^ Shift
              -> String -- ^ Plaintext
              -> String -- ^ Ciphertext
encryptCaesar shift = if (shift <= 0) then error "Shift must be positive number"
                                      else map (shiftLetter shift)

inverseShift :: Int -> Int
inverseShift = (-) 26 . flip rem 26

-- | Decrypt the given plaintext using Caesar cipher.
-- For detailed specification, see 'encryptCaesar'.
--
-- For every valid shift 'i' and for every plaintext string 's' it should hold
-- that @decryptCaesar i (encryptCaesar i s) == s@.
--
-- >>> decryptCaesar 5 "fgh"
-- "abc"
--
-- >>> decryptCaesar (-3) "abc"
-- *** Exception: Incorrect shift.

decryptCaesar :: Int    -- ^ Shift
              -> String -- ^ Plaintext
              -> String -- ^ Ciphertext
decryptCaesar shift = if (shift <= 0) then error "Shift must be positive number"
                                      else map (shiftLetter (inverseShift shift))

-- | Adds characters from the input 'String' and from key 'String' modulo 26.
-- It works only on characters @'a'..'z'@.  If the key string is shorter then
-- input string it is repeated.
--
-- Similarly to 'encryptCaesar' you can use 'fromEnum' and 'toEnum' to calculate character codes. For example, sum of @'b'@ and @'c'@ gives @'d'@.
--
-- As a special case, if the key is empty the result is the same as input.
--
-- >>>  encryptVigenere "gfe" "abcdefg"
-- "gggjjjm"
--
-- >>> encryptVigenere "heslo" "hello world"
-- "oidwc agczk"
--
-- >>> encryptVigenere "" "hello world"
-- "hello world"
encryptVigenere :: String -- ^ Key string
                -> String -- ^ Plaintext
                -> String -- ^ Ciphertext
encryptVigenere keyString = zipWith shiftLetter (cycle $ if (null keyString) then [0] else map normalizeLetter keyString)

-- | Decrypt the given plaintext using Vigenere cipher.
-- For detailed specification, see 'encryptVigenere'.
--
-- For every valid key string @k@ and for every plaintext string @s@ it should
-- hold that @decryptVigenere k (encryptVigenere k s) == s@.
--
-- >>> decryptVigenere "abcd" "abcd"
-- "aaaa"
--
-- >>> decryptVigenere "" "hello"
-- "hello"
decryptVigenere :: String -- ^ Key string
                -> String -- ^ Plaintext
                -> String -- ^ Ciphertext
decryptVigenere keyString = zipWith shiftLetter (cycle $ map inverseShift $ if (null keyString) then [0] else map normalizeLetter keyString)

-- | Combines several ciphers into one, using each one for a block of given
-- size. For example @applyMultiple [f, g] 4 plain@ applies cipher @f@ to first 4
-- characters of @plain@, cipher @g@ to next 4, then again @f@… The last block
-- can be shorter than given number (length of plaintext need not be multiple
-- of block length).
--
-- The first argument is list of encryption (or decryption) functions, these
-- function are used for encryption (or decryption) of each blocks of the input
-- text (each block has length given by the second argument). Functions are
-- repeated in the same way as the key for Vigenere cipher.
--
-- * In the case the length of the input string is not divisible by block
-- length the last block can be shorter.
--
-- * In the case the block length is less or equal to zero, the resulting
-- string is same as the input string.
--
-- * In the case the list of functions is empty, the resulting string is the
-- same as the input string.
--
-- >>> applyMultiple [encryptCaesar 1, encryptCaesar 2, encryptCaesar  3] 2 "aaaaaaaaaaaaa"
-- "bbccddbbccddb"
--
-- >>> applyMultiple [encryptVigenere "abc", encryptVigenere "bce", encryptCaesar 5] 4 "abcdefghijklmnopq"
-- "acedfhkinopqmoqpr"
--
-- >>> applyMultiple [decryptVigenere "abc", decryptVigenere "bce", decryptCaesar 5] 4 "acedfhkinopqmoqpr"
-- "abcdefghijklmnopq"
--
-- >>> applyMultiple [] 4 "hello"
-- "hello"
--
-- >>> applyMultiple [encryptCaesar 2, encryptCaesar 12] (-3) "hello"
-- "hello"

applyMultiple :: [String -> String] -- ^ List of encryption functions
              -> Int                -- ^ Block size
              -> String             -- ^ Plaintext
              -> String             -- ^ Ciphertext
applyMultiple [] _ p = p
applyMultiple functions blockSize plaintext = if (blockSize <= 0) then plaintext
                                                                  else applyMultiple' (cycle functions) blockSize $ splitAt blockSize plaintext

applyMultiple' :: [String -> String] -> Int -> (String,String) -> String
applyMultiple' _ _ ([],[]) = []
applyMultiple' functions@(f:fs) blockSize (processedBlock,rest) = (f processedBlock) ++ applyMultiple' fs blockSize (splitAt blockSize rest)

-- | Interactive cryptanalysis assistant for monoalphabetic substitution cipher.
--
-- Minimal requirements:
--
--   * The assistant displays current state of plaintext/ciphertext
--   * The assistant displays currently applied substitutions
--   * You can add a new substitution
--   * You can delete a substitution
--   * You can delete all substitutions at once
--   * You can close the assistant returning the final substitution
--   * The substitution currently applied need not be correct permuation as
--   defined in 'encryptSubstitution'
--
-- The outputs below are just an example, you don't have to adhere
-- to that syntax (as long as you support the minimal functionality above).
--
-- @
-- >>>  assistant "abcdef"
--
-- Current state of decryption (CIPHERTEXT, plaintext):
-- ABCDEF
-- Current substitutions:
--
-- Available commands:
--   a (add new substitution pair)
--   d (delete substitution pair)
--   r (reset current substitution)
--   q (quit assistant)
-- Command choice: a
-- Ciphertext letter: a
-- Plaintext letter: h
--
-- Current state of decryption (CIPHERTEXT, plaintext):
-- hBCDEF
-- Current substitutions: h->A
--
-- Available commands:
--   a (add new substitution pair)
--   d (delete substitution pair)
--   r (reset current substitution)
--   q (quit assistant)
-- Command choice: a
-- Ciphertext letter: b
-- Plaintext letter: e
--
-- Current state of decryption (CIPHERTEXT, plaintext):
-- heCDEF
-- Current substitutions: e->B, h->A
--
-- Available commands:
--   a (add new substitution pair)
--   d (delete substitution pair)
--   r (reset current substitution)
--   q (quit assistant)
-- Command choice: r
--
-- Current state of decryption (CIPHERTEXT, plaintext):
-- ABCDEF
-- Current substitutions:
--
-- Available commands:
--   a (add new substitution pair)
--   d (delete substitution pair)
--   r (reset current substitution)
--   q (quit assistant)
-- Command choice: q
-- []
-- @
--
-- == BONUS
--
-- Add any other functions to the assistant you find useful.
-- You can get up to 5 additional point depending on the functionality
-- you implement.

lowerCaseEncrypt :: [(Char,Char)] -> Char -> Char
lowerCaseEncrypt permutation c = maybe (toUpper c) id $ lookup (toLower c) permutation

readCipherPlainTextLetters :: IO (Char,Char)
readCipherPlainTextLetters = do
    putStr "Ciphertext letter:"
    c <- getCharFromLine
    putStr "Plaintext letter:"
    p <- getCharFromLine
    return (c,p)

getCharFromLine :: IO Char
getCharFromLine = do
    line <- getLine
    return $ maybe ' ' id $ find (not . isSpace) line

processCommand :: Char -> [(Char,Char)] -> IO [(Char,Char)]
processCommand command substitutions = case command of 
                                         'q' -> return substitutions
                                         'r' -> putStrLn "Set of substitutions erased" >> return []
                                         'a' -> do
                                             (c,p) <- readCipherPlainTextLetters
                                             if uncurry (on (||) isSpace) (c,p) then 
                                                do
                                                    putStrLn "Space entered!"
                                                    return substitutions
                                             else case find (\(a,b) -> (||) (b == c) (a == p) ) substitutions of
                                                    Just pair@(a,b) -> do
                                                        putStrLn $ "Set of substitution rules already contains pair " ++ show pair
                                                        return substitutions
                                                    Nothing -> do
                                                        putStrLn $ "Pair " ++ show (p,c) ++ " added into substitutions"
                                                        return $ substitutions ++ [(p,c)]
                                         'd' -> do
                                             pair <- readCipherPlainTextLetters
                                             if uncurry (on (||) isSpace) pair then do
                                                 putStrLn "Space entered!"
                                                 return substitutions
                                             else if elem pair substitutions then do
                                                     putStrLn $ "Pair " ++ show pair ++ " deleted"
                                                     return $ delete pair substitutions
                                                  else do
                                                     putStrLn $ "Pair " ++ show pair ++ " not found"
                                                     return $ substitutions
                                         _ -> putStrLn "Invalid command!" >> return substitutions

help :: IO ()
help = putStrLn "\ta (add new substitution pair)" >> putStrLn "\td (delete substitution pair)" >>
       putStrLn "\tr (reset current substitution)" >> putStrLn "\tq (quit assistant)"

assistant :: String            -- ^ Ciphertext
          -> IO [(Char, Char)] -- ^ Final substitution
assistant = flip assistantRec []

assistantRec :: String -> [(Char,Char)] -> IO [(Char,Char)]
assistantRec cryptotext substitutions = do
    putStrLn "Current state of decryption (CIPHERTEXT, plaintext)"
    putStrLn $ map (lowerCaseEncrypt substitutions) cryptotext
    putStr "Current substitutions: "
    putStrLn $ intercalate "," $ map (\(a,b) -> a:[] ++ "->" ++ (toUpper b) : []) substitutions
    help
    putStr "Current choice: "
    commandString <- getLine
    let commandChar = maybe ' ' id (find (not . isSpace) commandString)
    if (commandChar == ' ') then do
        putStrLn "No command entered"
        assistantRec cryptotext substitutions
    else do
        substitutions <- processCommand commandChar substitutions
        if (commandChar == 'q') then 
            if (not $ isValidSubstitution substitutions) then do
                putStrLn "Resulting substitution is not valid"
                return []
            else return substitutions 
        else assistantRec cryptotext substitutions
