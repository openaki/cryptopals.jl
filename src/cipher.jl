using AES

export single_key_xor, single_key_xor_decrypt, single_key_xor_decrypt_key, detect_single_char_xor, repeating_key_xor_decrypt, break_repeating_key_xor, aes_128_ecb_decrypt, aes_128_ecb_detect

function single_key_xor_it(bs, b :: UInt8) 
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

function single_key_xor_decrypt_key(bs) :: UInt8
    xors = Iterators.map(x -> single_key_xor_it(bs, x), (UInt8(0):UInt8(255))) 
    ans = findmax(score_for_english, xors)[2]
    return UInt8(ans - 1)
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

function repeating_key_xor_decrypt(bs, key :: Bytes.T) #:: Bytes.T
    ans = Vector{UInt8}(undef, length(bs))

    zipped = Iterators.cycle(key) |> it -> Iterators.zip(bs, it)
    for (i, (a, b)) in enumerate(zipped)
        ans[i] = Base.xor(a, b)
    end
    return ans
        
end

function break_repeating_key_xor(bs :: Bytes.T) :: String

    blocks = 30
    max_score = typemax(Int)
    max_key_size = 0
    for key_size in 2:40
        score = Iterators.partition(bs, key_size) |> 
                it -> Iterators.zip(it, Iterators.partition(bs[key_size+1:length(bs)], key_size)) |> 
                it -> Iterators.take(it, blocks) |> it -> Iterators.map(x -> Bytes.hamming_distance(x[1], x[2]), it) |> sum

        score = score / key_size
        max_score > score && ((max_score, max_key_size) = (score, key_size))
    end

    multi_key = Vector{UInt8}(undef, max_key_size)

    v = Vector{UInt8}(undef, length(bs) ÷ max_key_size + 1)
    for i in 1:max_key_size
        for (i, j) in enumerate(i:max_key_size:length(bs))
            v[i] = bs[j]
        end
        multi_key[i] = single_key_xor_decrypt_key(v)
    end
    dec = repeating_key_xor_decrypt(bs, multi_key)
    return (dec |> String)

end

function aes_128_ecb_decrypt(bs :: Bytes.T, key :: Bytes.T) :: String
    aes_key = AES128Key(key)
    aes_cache = AES.gen_cache(aes_key, AES.ECB)
    AES.AESECB_D(bs, aes_key, aes_cache) |> String
    
end

function get_same_block_count(bs, block_size = 16)
    total_blocks = length(bs) ÷ block_size + 1

    different_blocks = Set{Bytes.T}()
    for b in Iterators.partition(bs, block_size)
        push!(different_blocks, b)
    end
    ans = total_blocks - length(different_blocks)
    println(ans, " " , bs[1:5])
    return ans
    
end

function aes_128_ecb_detect(bs) :: Bytes.T

    argmax(get_same_block_count, bs)
end
