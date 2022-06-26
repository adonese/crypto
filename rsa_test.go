//Package crypto implements IPIN encryption as per EBS
// It supports libraries in different languages including: Go, Python, JavaScript, Java and Dart.
// The code is battle-tested and has been used in production for years.
package crypto

import (
	"reflect"
	"testing"
)

func TestEncryptNoebs(t *testing.T) {
	const pubKey1 = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR0lD1Fyia1GmodfSzKaiwhiZ0
0OMcHjTy7cxZsENmLxO0i0RQ0o2PHqz+cMX2CEEpUEDIPatv3xuVln53S7NTMFxY
h3RG12VafI3XtMZTNovcLuNp2CYPLz+/2IVvCktsTp9it3pDqB5MLNTWMSNWyuk3
qiJkr3VctmXoxdRvFwIDAQAB
-----END PUBLIC KEY-----`
	want := "EUL3VYG7gffmD8wfPf2Dr3EHbH9Aimp68Qa3cPNkXu8jjOuTzIUXdn7sE8XRpFdZxxYRCyQYPc5Leka7DX70UdhmFvrAPbViZ7oeWEZ7QkR6iYSf+xu27oNFozynMye6gwbZyKH7RVXg0s6PjAW2HxiO/bSFMtHftxL06qnwaDA="
	type args struct {
		pubkey  string
		payload string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"RSA Encrypt example", args{pubkey: pubKey1, payload: "1234"}, want, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := EncryptNoebs(tt.args.pubkey, tt.args.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("EncryptNoebs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("EncryptNoebs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestDecryptNoebs(t *testing.T) {
	const myKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDR0lD1Fyia1GmodfSzKaiwhiZ00OMcHjTy7cxZsENmLxO0i0RQ
0o2PHqz+cMX2CEEpUEDIPatv3xuVln53S7NTMFxYh3RG12VafI3XtMZTNovcLuNp
2CYPLz+/2IVvCktsTp9it3pDqB5MLNTWMSNWyuk3qiJkr3VctmXoxdRvFwIDAQAB
AoGBALLJ57owdaUZAr9NY6mXAesJJJO9uwgmpS+recmi7IuR6dSaJyhHgeBGX1qg
dc7j0cKGY+08v2ygTDz28+RrWO0q4kV0iGZ0N2AbmX34AMQwYWq2wrszokAXAASL
hlekVY2/eFtzdVbb5wqhZNCrPxD/EnJ5cs2kofaG40jDfqVhAkEA7NyBWv4fS1ns
Lgjv61EeB/BohpFk8mfaMNmImrakupXQIH5tT8Sh9+kHIiTjapopIq5WPzWjtw8N
WUxgnkqB7QJBAOLGfZqaJ309DHwPeCn9EG4LkS3OPe6vSDkrEDkLmVJOyT9RqoS7
p131duEQuHImsLgAj/wEnTdVVYCqMUMQpJMCQQDH+adQzopXUNVBTJRaxUKoi0WE
j459xkaFxbM6hAdx7HgqZvMdTLM+nkRChIhogT1HpY71kPDm5dNsWDqeieNFAkEA
wvm75l/h0ejaQhQe0aMWLDdfxE1NrFkiNJzU3ucdFMpOd1Vk0ahx9vPkGRACNYsU
Z698HEdvULLax7wMjMfTZwJAAIrwM2myhTc5it1/dY93FoTiKwHgK7hYmLXr6I8u
QCS3eL4elcKvcS1lhrZiNpK2yGNYdlqH4jku/lnnhW03mg==
-----END RSA PRIVATE KEY-----`
	want2 := "sQGPm5OO0HCxix8VV2XIF9NrCFgFqfKmpqtp43Btq90BEc3Yx2m2o446Oa9NyPEzzq8E3oluAyhHFAah3q1607DG/pbHqeYzgJ+bfC5kHgwo2aXzvo7EbS6reae1CLAvfIE177D9yioqgdu1GbN9EUvfpT7NiSYRwZmfSU4i434="
	type args struct {
		privkey string
		payload string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"noebs decryption example", args{privkey: myKey, payload: "1234"}, want2, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := DecryptNoebs(tt.args.privkey, tt.args.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("DecryptNoebs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("DecryptNoebs() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSign(t *testing.T) {
	const myKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDR0lD1Fyia1GmodfSzKaiwhiZ00OMcHjTy7cxZsENmLxO0i0RQ
0o2PHqz+cMX2CEEpUEDIPatv3xuVln53S7NTMFxYh3RG12VafI3XtMZTNovcLuNp
2CYPLz+/2IVvCktsTp9it3pDqB5MLNTWMSNWyuk3qiJkr3VctmXoxdRvFwIDAQAB
AoGBALLJ57owdaUZAr9NY6mXAesJJJO9uwgmpS+recmi7IuR6dSaJyhHgeBGX1qg
dc7j0cKGY+08v2ygTDz28+RrWO0q4kV0iGZ0N2AbmX34AMQwYWq2wrszokAXAASL
hlekVY2/eFtzdVbb5wqhZNCrPxD/EnJ5cs2kofaG40jDfqVhAkEA7NyBWv4fS1ns
Lgjv61EeB/BohpFk8mfaMNmImrakupXQIH5tT8Sh9+kHIiTjapopIq5WPzWjtw8N
WUxgnkqB7QJBAOLGfZqaJ309DHwPeCn9EG4LkS3OPe6vSDkrEDkLmVJOyT9RqoS7
p131duEQuHImsLgAj/wEnTdVVYCqMUMQpJMCQQDH+adQzopXUNVBTJRaxUKoi0WE
j459xkaFxbM6hAdx7HgqZvMdTLM+nkRChIhogT1HpY71kPDm5dNsWDqeieNFAkEA
wvm75l/h0ejaQhQe0aMWLDdfxE1NrFkiNJzU3ucdFMpOd1Vk0ahx9vPkGRACNYsU
Z698HEdvULLax7wMjMfTZwJAAIrwM2myhTc5it1/dY93FoTiKwHgK7hYmLXr6I8u
QCS3eL4elcKvcS1lhrZiNpK2yGNYdlqH4jku/lnnhW03mg==
-----END RSA PRIVATE KEY-----`
	want := "388a6e734f7ff2171eb73f4cfc4e08bd30da6381c0083b8c477328842e1a48e00deaf995f2b145c32918c67b11f89e2917dae7b40cd70d89f02975009b291cce6b784acab9b9be54f3e44c5822722fc491d7bd96e15b4e88a43c61124f453cbd76e4aba1d4f95e3ec8c0efcbade7bc6b28fab76cb725a65652d92213c942b08d"
	type args struct {
		privkey string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"test-sign", args{privkey: myKey}, want, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Sign(tt.args.privkey)
			if (err != nil) != tt.wantErr {
				t.Errorf("Sign() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Sign() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	pubKey := `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDR0lD1Fyia1GmodfSzKaiwhiZ0
0OMcHjTy7cxZsENmLxO0i0RQ0o2PHqz+cMX2CEEpUEDIPatv3xuVln53S7NTMFxY
h3RG12VafI3XtMZTNovcLuNp2CYPLz+/2IVvCktsTp9it3pDqB5MLNTWMSNWyuk3
qiJkr3VctmXoxdRvFwIDAQAB
-----END PUBLIC KEY-----`
	signature := "388a6e734f7ff2171eb73f4cfc4e08bd30da6381c0083b8c477328842e1a48e00deaf995f2b145c32918c67b11f89e2917dae7b40cd70d89f02975009b291cce6b784acab9b9be54f3e44c5822722fc491d7bd96e15b4e88a43c61124f453cbd76e4aba1d4f95e3ec8c0efcbade7bc6b28fab76cb725a65652d92213c942b08d"
	want := true

	key := encode(pubKey)
	type args struct {
		pubkey  string
		payload string
	}
	tests := []struct {
		name    string
		args    args
		want    bool
		wantErr bool
	}{
		{"test-verify", args{pubkey: key, payload: signature}, want, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Verify(tt.args.pubkey, tt.args.payload)
			if (err != nil) != tt.wantErr {
				t.Errorf("Verify() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("Verify() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_encode(t *testing.T) {
	const myKey = `
-----BEGIN RSA PRIVATE KEY-----
MIICXgIBAAKBgQDR0lD1Fyia1GmodfSzKaiwhiZ00OMcHjTy7cxZsENmLxO0i0RQ
0o2PHqz+cMX2CEEpUEDIPatv3xuVln53S7NTMFxYh3RG12VafI3XtMZTNovcLuNp
2CYPLz+/2IVvCktsTp9it3pDqB5MLNTWMSNWyuk3qiJkr3VctmXoxdRvFwIDAQAB
AoGBALLJ57owdaUZAr9NY6mXAesJJJO9uwgmpS+recmi7IuR6dSaJyhHgeBGX1qg
dc7j0cKGY+08v2ygTDz28+RrWO0q4kV0iGZ0N2AbmX34AMQwYWq2wrszokAXAASL
hlekVY2/eFtzdVbb5wqhZNCrPxD/EnJ5cs2kofaG40jDfqVhAkEA7NyBWv4fS1ns
Lgjv61EeB/BohpFk8mfaMNmImrakupXQIH5tT8Sh9+kHIiTjapopIq5WPzWjtw8N
WUxgnkqB7QJBAOLGfZqaJ309DHwPeCn9EG4LkS3OPe6vSDkrEDkLmVJOyT9RqoS7
p131duEQuHImsLgAj/wEnTdVVYCqMUMQpJMCQQDH+adQzopXUNVBTJRaxUKoi0WE
j459xkaFxbM6hAdx7HgqZvMdTLM+nkRChIhogT1HpY71kPDm5dNsWDqeieNFAkEA
wvm75l/h0ejaQhQe0aMWLDdfxE1NrFkiNJzU3ucdFMpOd1Vk0ahx9vPkGRACNYsU
Z698HEdvULLax7wMjMfTZwJAAIrwM2myhTc5it1/dY93FoTiKwHgK7hYmLXr6I8u
QCS3eL4elcKvcS1lhrZiNpK2yGNYdlqH4jku/lnnhW03mg==
-----END RSA PRIVATE KEY-----`
	want := "Ci0tLS0tQkVHSU4gUlNBIFBSSVZBVEUgS0VZLS0tLS0KTUlJQ1hnSUJBQUtCZ1FEUjBsRDFGeWlhMUdtb2RmU3pLYWl3aGlaMDBPTWNIalR5N2N4WnNFTm1MeE8waTBSUQowbzJQSHF6K2NNWDJDRUVwVUVESVBhdHYzeHVWbG41M1M3TlRNRnhZaDNSRzEyVmFmSTNYdE1aVE5vdmNMdU5wCjJDWVBMeisvMklWdkNrdHNUcDlpdDNwRHFCNU1MTlRXTVNOV3l1azNxaUprcjNWY3RtWG94ZFJ2RndJREFRQUIKQW9HQkFMTEo1N293ZGFVWkFyOU5ZNm1YQWVzSkpKTzl1d2dtcFMrcmVjbWk3SXVSNmRTYUp5aEhnZUJHWDFxZwpkYzdqMGNLR1krMDh2MnlnVER6MjgrUnJXTzBxNGtWMGlHWjBOMkFibVgzNEFNUXdZV3Eyd3Jzem9rQVhBQVNMCmhsZWtWWTIvZUZ0emRWYmI1d3FoWk5DclB4RC9Fbko1Y3Mya29mYUc0MGpEZnFWaEFrRUE3TnlCV3Y0ZlMxbnMKTGdqdjYxRWVCL0JvaHBGazhtZmFNTm1JbXJha3VwWFFJSDV0VDhTaDkra0hJaVRqYXBvcElxNVdQeldqdHc4TgpXVXhnbmtxQjdRSkJBT0xHZlpxYUozMDlESHdQZUNuOUVHNExrUzNPUGU2dlNEa3JFRGtMbVZKT3lUOVJxb1M3CnAxMzFkdUVRdUhJbXNMZ0FqL3dFblRkVlZZQ3FNVU1RcEpNQ1FRREgrYWRRem9wWFVOVkJUSlJheFVLb2kwV0UKajQ1OXhrYUZ4Yk02aEFkeDdIZ3Fadk1kVExNK25rUkNoSWhvZ1QxSHBZNzFrUERtNWROc1dEcWVpZU5GQWtFQQp3dm03NWwvaDBlamFRaFFlMGFNV0xEZGZ4RTFOckZraU5KelUzdWNkRk1wT2QxVmswYWh4OXZQa0dSQUNOWXNVClo2OThIRWR2VUxMYXg3d01qTWZUWndKQUFJcndNMm15aFRjNWl0MS9kWTkzRm9UaUt3SGdLN2hZbUxYcjZJOHUKUUNTM2VMNGVsY0t2Y1MxbGhyWmlOcEsyeUdOWWRscUg0amt1L2xubmhXMDNtZz09Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0t"
	type args struct {
		data string
	}
	tests := []struct {
		name    string
		args    args
		want    string
		wantErr bool
	}{
		{"test-encoding", args{data: myKey}, want, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := encode(tt.args.data)
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("encode() = %v, want %v", got, tt.want)
			}
		})
	}
}
