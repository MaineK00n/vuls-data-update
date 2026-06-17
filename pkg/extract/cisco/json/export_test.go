package json

// ConvertProductName exposes convertProductName to external (black-box) tests.
func ConvertProductName(name string) (base, concrete string, err error) {
	return convertProductName(name)
}
