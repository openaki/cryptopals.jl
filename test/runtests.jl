using cryptopals
using cryptopals.Bytes
using Test

function get_input_file(base_file)
	repl_file_name = "./test/inputs/" * base_file
	isfile(repl_file_name) && return repl_file_name
	return "./inputs/" * base_file
end

@testset "hex_utils" begin
	@test from_string("45a73") == [0x34,0x35,0x61,0x37, 0x33]
	@test from_hex("45a731") ==  [0x45, 0xa7, 0x31]

	@test Bytes.bits_to_byte([0x01, 0x00, 0x00, 0x01, 0x01, 0x00, 0x01, 0x01]) == 155
	@test cryptopals.to_hex([0xA0, 0x05]) == "a005"

	test_cases = [
				  ("TWFu", "Man"),
				  ("TWE=", "Ma"),
				  ("TQ==", "M"),
				  ("cGxlYXN1cmUu", "pleasure."),
				  ("bGVhc3VyZS4=", "leasure."),
				  ("ZWFzdXJlLg==", "easure."),
				  ("YXN1cmUu", "asure."),
				  ("c3VyZS4=", "sure."),
				  ("c3VyZS4=", "sure."),
				  ]
	for (b64, bytes) in test_cases
		@test from_bytes(from_base64(b64)) == bytes
	end

	@test to_hex(from_base64("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t")) == "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
	
	for (b64, bytes) in test_cases
		@test to_base64(from_string(bytes)) == b64
	end

	@test to_base64(from_hex("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d")) == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"


	@test Bytes.xor(from_hex("1c0111001f010100061a024b53535009181c"), from_hex("686974207468652062756c6c277320657965")) == from_hex("746865206b696420646f6e277420706c6179")

end

@testset "cipher" begin

	@test single_key_xor_decrypt(from_hex("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")) == "Cooking MC's like a pound of bacon"


	file_name = get_input_file("challenge1_4.txt")
	file_content = readlines(file_name) |> it -> Iterators.map(from_hex, it)
	@test detect_single_char_xor(file_content) == "Now that the party is jumping\n"

end

