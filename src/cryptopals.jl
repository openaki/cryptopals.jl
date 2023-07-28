module cryptopals

include("Bytes.jl")
using .Bytes

include("cipher.jl")

greet() = print("Hello World!")

end # module cryptopals
