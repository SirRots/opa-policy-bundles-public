package lightbulbs

import rego.v1

default allow_michael = false

allow_michael if {
  input.method == "GET"
  print("Allowed because of GET")
}
