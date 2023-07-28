export single_key_xor, single_key_xor_decrypt, detect_single_char_xor

function single_key_xor_it(bs :: Bytes.T, b :: UInt8) 
    Iterators.map(i -> Base.xor(i, b), bs)
end

function single_key_xor(bs :: Bytes.T, b :: UInt8) :: Bytes.T
    single_key_xor_it(bs, b) |> collect
end

function score_for_english(bs) :: Int
    score = 0
    for b in bs
        b = Char(b)
        b == 'e' && (score += 10)
        b == 't' && (score += 9)
        b == 'o' && (score += 8)
        b == 'i' && (score += 7)
        b == 'n' && (score += 6)
        isspace(b) && (score += 5)
        islowercase(b) && (score += 4)
        isuppercase(b) && (score += 2)
        isnumeric(b) && (score += 1)
        score -= 2
    end
    return score

end

function sort_and_print(ls, solutions = 1)
    sort!(ls, lt = Base.isgreater, by = score_for_english)
    for (i, st) in enumerate(Iterators.take(ls, solutions))
        println(i, String(st))
    end
end

function single_key_xor_decrypt_it(bs)
    xors = Iterators.map(x -> single_key_xor_it(bs, x), (UInt8(0):UInt8(255))) 
    # sort_and_print(xors)
    
    ans = argmax(score_for_english, xors)
    return ans
        
end

function single_key_xor_decrypt(bs) :: String
    ans = single_key_xor_decrypt_it(bs)
    return String(ans |> collect)
        
end

function detect_single_char_xor(bs)  :: String
    decrypted = Iterators.map(single_key_xor_decrypt, bs)

    ans = argmax(score_for_english,  decrypted)
    return String(ans |> collect)

end
