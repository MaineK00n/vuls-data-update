package json

// ConvertProductName exposes convertProductName to external (black-box) tests.
func ConvertProductName(name string) (string, error) {
	return convertProductName(name)
}
