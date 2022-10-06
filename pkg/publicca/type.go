package publicca

type EABKey struct {
	ResourceId string `json:"resourceId"`
	KeyId      string `json:"keyId,omitempty"`
	HmacKey    string `json:"hmacKey,omitempty"`
}
