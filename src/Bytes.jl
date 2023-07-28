module Bytes

export from_string, from_hex, from_base64, from_bytes, to_hex, to_base64, xor

T = Vector{UInt8}

function from_string(input:: String) :: T
    ans = Vector{UInt8}(undef, length(input))
    for (i, c) in enumerate(input)
        ans[i] = c
    end
    return ans
end

function from_bytes(input) :: String
    ans = Vector{Char}(undef, length(input))
    for (i, c) in enumerate(input)
        ans[i] = c
    end
    return String(ans)
end

function to_hex(input) :: String
    Iterators.map(x -> string(x, base=16, pad=2), input) |> 
        it -> join(it, "", "") |>
        string
end

function from_hex(hex:: String) :: T
    ans = Vector{UInt8}(undef, length(hex) ÷ 2)
    if length(hex) %  2 != 0
        throw("Hex String needs to be even size")
    end
    function to_num(x:: Char)
        if x >= '0' && x <='9'
            x - '0'
        elseif x >= 'a' && x <='f'
            10 + (x - 'a')
        else
            10 + (x - 'A')
        end
    end

    for (i, x) in enumerate(Iterators.partition(hex, 2))
        (a, b) = (x[1],  x[2])
        ans[i] = 16 * to_num(a) + to_num(b)
    end
    return ans
end

function base64_char_to_num(x:: Char) :: UInt8
    if x >= 'A' && x <='Z'
        x - 'A'
    elseif x >= 'a' && x <='z'
        26 + (x - 'a')
    elseif x >= '0' && x <='9'
        52 + (x - '0')
    elseif x == '+'
        62
    elseif x == '/'
        63
    elseif x == '='
        64
    else
        throw("Bad char in base64 $(x)")
    end
end

function base64_num_to_char(b) :: Char
    n = 0
    mult = 32

    for x in b
        n += x * mult
        mult = mult ÷ 2
    end

    if n < 26
        'A' + n
    elseif n < 52
        n - 26 + 'a'
    elseif n < 62
        n - 52 + '0'
    elseif n < 63
        '+'
    else
        '/'
    end
end
    
function byte_to_bits(byte :: UInt8, num = 6)
    ((num-1):-1:0) |> it -> Iterators.map(x -> (byte >> x) & 0x1 , it)
end

function bits_to_byte(bits)
    multiplier = 128
    val = 0
    for b in bits
        val += multiplier * b
        multiplier = multiplier ÷ 2
    end 
    return UInt8(val)

end

function from_base64(s :: String) 
    num_equals = 0
    for c in s |> reverse 
        if c == '=' num_equals+=1
        else break
        end
    end

    bits = length(s) - num_equals
    bits = (bits * 6) - (num_equals * 2)

    Iterators.map(base64_char_to_num,s) |> 
      it -> Iterators.filter(!=(64),it) |> 
      it -> Iterators.flatmap(byte_to_bits, it) |>
      it -> Iterators.take(it, bits) |>
      it -> Iterators.partition(it, 8) |>
      it -> Iterators.map(bits_to_byte, it) |>
      collect
end

function to_base64(b :: T) :: String
    byte_to_bits_local(bit) = byte_to_bits(bit, 8)

    padding_len = length(b) % 3
    if padding_len > 0
        padding_len = 3 - padding_len
    end

    padding_it = Iterators.repeated('=', padding_len)


    b |> it -> Iterators.flatmap(byte_to_bits_local, it) |> 
    it -> Iterators.partition(it, 6) |> it -> Iterators.map(base64_num_to_char, it)  |> 
    it -> Iterators.flatten((it, padding_it)) |> collect |> String
    
end

function xor(a :: T, b :: T) :: T
    ans = Vector{UInt8}(undef, length(a))
    for (i, (x, y)) in enumerate(Iterators.zip(a, b))
        ans[i] = Base.xor(x, y)
    end
    ans
end

end
