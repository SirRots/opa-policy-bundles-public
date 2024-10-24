package lightbulbs

import rego.v1

default allow_dante = false


allow if {
	correct_path #Defined in the helper function section below
	print("The path is correct")

	"policy", "dante" in input.uri_args
	print("Dante's policy is used")

	jwt.is_valid #Defined in the helper function section below
	print("The JWT is valid")

	allow_dante #Defined in policy_michael.rego
	print("Access is allowed per Dante's policy")
}

#allow_dante if {
#  	input.method == "POST"
#  	print("Allowed because of POST")
@	}
allow_dante if {
	jwt := {"claims": payload, "is_valid": valid} if {
	#Decodes the JWT bearer token and verifies its signature
		jwks := jwks_request(concat("",[iss,"/.well-known/jwks.json"])).raw_body
		constraints := {
		"cert": jwks,
		"iss": concat("",[iss,"/"]),
		"aud": aud
		}
		[valid,_,payload] := io.jwt.decode_verify(bearer_token,constraints)
}
}

