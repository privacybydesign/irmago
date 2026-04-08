package sdjwtvc

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"

	"github.com/privacybydesign/irmago/eudi/utils"
	"github.com/privacybydesign/irmago/testdata"
	"github.com/stretchr/testify/require"
)

// Credential profiles based on real production Yivi credentials.
// Attribute names match the official scheme definitions at https://schemes.yivi.app/pbdf/

// mobilenumberAttrs matches pbdf.pbdf.mobilenumber (1 attribute).
// Source: https://portal.yivi.app/attribute-index/credentials/production/pbdf/mobilenumber
func mobilenumberAttrs() map[string]string {
	return map[string]string{
		"mobilenumber": "+31612345678",
	}
}

// addressAttrs matches pbdf.gemeente.address (5 attributes).
// Source: https://portal.yivi.app/attribute-index/credentials/production/gemeente/address
func addressAttrs() map[string]string {
	return map[string]string{
		"street":      "Heidelberglaan",
		"houseNumber": "15",
		"zipcode":     "3584 CS",
		"city":        "Utrecht",
		"municipality": "Utrecht",
	}
}

// personalDataAttrs matches pbdf.gemeente.personalData (18 attributes).
// Source: https://portal.yivi.app/attribute-index/credentials/production/gemeente/personalData
func personalDataAttrs() map[string]string {
	return map[string]string{
		"initials":       "J.W.",
		"firstnames":     "Jan Willem",
		"prefix":         "de",
		"familyname":     "Jong",
		"fullname":       "Jan Willem de Jong",
		"gender":         "M",
		"nationality":    "Nederlandse",
		"surname":        "de Jong",
		"dateofbirth":    "1990-01-15",
		"cityofbirth":    "Amsterdam",
		"countryofbirth": "Nederland",
		"over12":         "Yes",
		"over16":         "Yes",
		"over18":         "Yes",
		"over21":         "Yes",
		"over65":         "No",
		"bsn":            "999999990",
		"digidlevel":     "Substantieel",
	}
}

// passportAttrs matches pbdf.pbdf.passport (18 attributes, without photo).
// Source: https://portal.yivi.app/attribute-index/credentials/production/pbdf/passport
func passportAttrs() map[string]string {
	return map[string]string{
		"documentNumber":       "SPECI2021",
		"documentType":         "P",
		"firstName":            "Jan Willem",
		"lastName":             "De Jong",
		"nationality":          "Nederlandse",
		"dateOfBirth":          "19900115",
		"yearOfBirth":          "1990",
		"dateOfExpiry":         "20310330",
		"gender":               "M",
		"country":              "NLD",
		"over12":               "Yes",
		"over16":               "Yes",
		"over18":               "Yes",
		"over21":               "Yes",
		"over65":               "No",
		"isEuCitizen":          "Yes",
		"activeAuthentication": "valid",
	}
}

// generateFakeJPEGPhoto generates a fake JPEG-like photo payload of the given byte size.
// In production, this would be an actual JPEG portrait photo embedded in the credential.
func generateFakeJPEGPhoto(sizeBytes int) string {
	data := make([]byte, sizeBytes)
	// Fill with a deterministic pattern so results are reproducible
	for i := range data {
		data[i] = byte(i % 256)
	}
	return base64.StdEncoding.EncodeToString(data)
}

// passportWithPhotoAttrs matches pbdf.pbdf.passport including the photo attribute.
// The photo attribute contains a base64-encoded portrait image. Photo sizes tested
// represent realistic JPEG portrait sizes: 15KB, 50KB, 100KB, 200KB.
func passportWithPhotoAttrs(photoSizeBytes int) map[string]string {
	attrs := passportAttrs()
	attrs["photo"] = generateFakeJPEGPhoto(photoSizeBytes)
	return attrs
}

type credentialProfile struct {
	name  string
	attrs map[string]string
}

func credentialProfiles() []credentialProfile {
	return []credentialProfile{
		{name: "pbdf.mobilenumber", attrs: mobilenumberAttrs()},
		{name: "gemeente.address", attrs: addressAttrs()},
		{name: "gemeente.personalData", attrs: personalDataAttrs()},
		{name: "pbdf.passport (no photo)", attrs: passportAttrs()},
		{name: "pbdf.passport+photo 15KB", attrs: passportWithPhotoAttrs(15 * 1024)},
		{name: "pbdf.passport+photo 50KB", attrs: passportWithPhotoAttrs(50 * 1024)},
		{name: "pbdf.passport+photo 100KB", attrs: passportWithPhotoAttrs(100 * 1024)},
		{name: "pbdf.passport+photo 200KB", attrs: passportWithPhotoAttrs(200 * 1024)},
	}
}

// buildSdJwtVc creates a complete SD-JWT VC for the given attributes, optionally with a KB-JWT.
func buildSdJwtVc(t *testing.T, attrs map[string]string, vct string, withKbJwt bool) SdJwtVc {
	t.Helper()

	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	require.NoError(t, err)

	disclosures, err := MultipleNewDisclosureContents(attrs)
	require.NoError(t, err)

	keyBinder := NewDefaultKeyBinderWithInMemoryStorage()
	holderKeys, err := keyBinder.CreateKeyPairs(1)
	require.NoError(t, err)

	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()

	sdJwt, err := NewSdJwtVcBuilder().
		WithHolderKey(holderKeys[0]).
		WithIssuerUrl("https://openid4vc.staging.yivi.app").
		WithVerifiableCredentialType(vct).
		WithDisclosures(disclosures).
		WithHashingAlgorithm(HashAlg_Sha256).
		WithIssuerCertificateChain(irmaAppCert).
		WithExpiresAt(1945394126).
		WithIssuedAt(1745394126).
		Build(jwtCreator)
	require.NoError(t, err)

	if withKbJwt {
		kbjwt, err := CreateKbJwt(sdJwt, keyBinder, "nonce-value", "https://verifier.example.com")
		require.NoError(t, err)
		sdJwt = AddKeyBindingJwtToSdJwtVc(sdJwt, kbjwt)
	}

	return sdJwt
}

// TestSdJwtVcSizeBenchmark measures the byte sizes of SD-JWT VCs across different
// credential profiles. This produces citable data about SD-JWT VC sizes for various
// credential types, from minimal (phone number) to worst-case (passport with photo).
func TestSdJwtVcSizeBenchmark(t *testing.T) {
	profiles := credentialProfiles()

	fmt.Println("=======================================================================")
	fmt.Println("SD-JWT VC Size Benchmark")
	fmt.Println("=======================================================================")
	fmt.Println()
	fmt.Printf("%-25s | %6s | %10s | %10s | %10s | %10s\n",
		"Credential Type", "Attrs", "Issuer JWT", "Discl.", "KB-JWT", "Total")
	fmt.Println(strings.Repeat("-", 90))

	for _, profile := range profiles {
		// Build without KB-JWT first to measure components
		sdJwtNoKb := buildSdJwtVc(t, profile.attrs, "benchmark.test."+profile.name, false)
		issuerJwt, disclosures, _, err := SplitSdJwtVc(sdJwtNoKb)
		require.NoError(t, err)

		// Build with KB-JWT for total size
		sdJwtWithKb := buildSdJwtVc(t, profile.attrs, "benchmark.test."+profile.name, true)

		// Measure KB-JWT size by splitting
		_, _, kbJwt, err := SplitSdJwtVc(sdJwtWithKb)
		require.NoError(t, err)

		issuerJwtBytes := len(issuerJwt)
		disclosureBytes := 0
		for _, d := range disclosures {
			disclosureBytes += len(d) + 1 // +1 for ~ separator
		}
		kbJwtBytes := 0
		if kbJwt != nil {
			kbJwtBytes = len(*kbJwt)
		}
		totalBytes := len(sdJwtWithKb)

		fmt.Printf("%-25s | %6d | %8d B | %8d B | %8d B | %8d B\n",
			profile.name,
			len(profile.attrs),
			issuerJwtBytes,
			disclosureBytes,
			kbJwtBytes,
			totalBytes,
		)
	}

	fmt.Println()
	fmt.Println("=======================================================================")
	fmt.Println("Human-Readable Summary")
	fmt.Println("=======================================================================")

	for _, profile := range profiles {
		sdJwt := buildSdJwtVc(t, profile.attrs, "benchmark.test."+profile.name, true)
		totalBytes := len(sdJwt)
		fmt.Printf("  %-25s: %8d bytes (%6.1f KB)\n", profile.name, totalBytes, float64(totalBytes)/1024)
	}

	fmt.Println()
}

// TestSdJwtVcBatchSizeBenchmark measures the total storage/transfer size for
// batch issuance at various batch sizes. Batch scaling is linear: total = single × count.
// Each disclosure event consumes one SD-JWT VC instance from the batch.
func TestSdJwtVcBatchSizeBenchmark(t *testing.T) {
	batchSizes := []uint{1, 5, 10, 25, 50, 100, 200}
	profiles := []credentialProfile{
		{name: "pbdf.mobilenumber", attrs: mobilenumberAttrs()},
		{name: "gemeente.address", attrs: addressAttrs()},
		{name: "gemeente.personalData", attrs: personalDataAttrs()},
		{name: "pbdf.passport (no photo)", attrs: passportAttrs()},
		{name: "pbdf.passport+photo 15KB", attrs: passportWithPhotoAttrs(15 * 1024)},
		{name: "pbdf.passport+photo 50KB", attrs: passportWithPhotoAttrs(50 * 1024)},
	}

	fmt.Println("=======================================================================")
	fmt.Println("SD-JWT VC Batch Issuance Size Matrix")
	fmt.Println("=======================================================================")
	fmt.Printf("Default batch size: %d, Max batch size: %d\n", 50, 200)
	fmt.Println("Scaling is LINEAR: total batch size = single instance size × batch count")
	fmt.Println()

	// First: show single instance size for each credential
	fmt.Println("--- Single SD-JWT VC instance size (without KB-JWT) ---")
	fmt.Println()
	type profileSize struct {
		profile          credentialProfile
		perInstanceBytes int
	}
	profileSizes := make([]profileSize, len(profiles))

	fmt.Printf("  %-30s | %6s | %10s\n", "Credential", "Attrs", "1x Size")
	fmt.Println("  " + strings.Repeat("-", 54))
	for i, profile := range profiles {
		sdJwt := buildSdJwtVc(t, profile.attrs, "benchmark.test."+profile.name, false)
		perInstanceBytes := len(sdJwt)
		profileSizes[i] = profileSize{profile: profile, perInstanceBytes: perInstanceBytes}
		fmt.Printf("  %-30s | %6d | %7.1f KB\n", profile.name, len(profile.attrs), float64(perInstanceBytes)/1024)
	}

	// Then: the full matrix
	fmt.Println()
	fmt.Println("--- Batch size matrix (total transfer/storage size) ---")
	fmt.Println()

	// Print header
	fmt.Printf("  %-30s |", "Credential \\ Batch size")
	for _, bs := range batchSizes {
		fmt.Printf(" %9s |", fmt.Sprintf("%dx", bs))
	}
	fmt.Println()
	fmt.Print("  " + strings.Repeat("-", 32))
	for range batchSizes {
		fmt.Print("+------------")
	}
	fmt.Println()

	for _, ps := range profileSizes {
		fmt.Printf("  %-30s |", ps.profile.name)
		for _, bs := range batchSizes {
			totalBytes := ps.perInstanceBytes * int(bs)
			fmt.Printf(" %10s |", formatBytes(totalBytes))
		}
		fmt.Println()
	}

	fmt.Println()
	fmt.Println("  Note: Batch scaling is linear because each SD-JWT VC instance in a batch")
	fmt.Println("  is a complete, independently usable credential with its own unique holder")
	fmt.Println("  key pair and disclosures. There is no shared state between instances.")
	fmt.Println()
	fmt.Println("  Each disclosure (presentation) event consumes one SD-JWT VC from the batch.")
	fmt.Println("  When all instances are used, the user must perform reissuance.")
	fmt.Println()
}

func formatBytes(b int) string {
	switch {
	case b < 1024:
		return fmt.Sprintf("%d B", b)
	case b < 1024*1024:
		return fmt.Sprintf("%.1f KB", float64(b)/1024)
	default:
		return fmt.Sprintf("%.1f MB", float64(b)/(1024*1024))
	}
}

// TestSdJwtVcComponentBreakdown provides a detailed breakdown of each component
// in an SD-JWT VC to understand where the bytes come from.
func TestSdJwtVcComponentBreakdown(t *testing.T) {
	fmt.Println("=======================================================================")
	fmt.Println("SD-JWT VC Component Breakdown (pbdf.mobilenumber)")
	fmt.Println("=======================================================================")

	attrs := mobilenumberAttrs()
	sdJwt := buildSdJwtVc(t, attrs, "pbdf.pbdf.mobilenumber", true)
	issuerJwt, disclosures, kbJwt, err := SplitSdJwtVc(sdJwt)
	require.NoError(t, err)

	totalSize := len(sdJwt)
	issuerSize := len(issuerJwt)
	kbSize := 0
	if kbJwt != nil {
		kbSize = len(*kbJwt)
	}
	separatorSize := len(disclosures) + 1 // one ~ per disclosure + one after issuer JWT

	disclosureTotalSize := 0
	fmt.Println()
	fmt.Println("Individual Disclosures:")
	for i, d := range disclosures {
		decoded, err := DecodeDisclosure(d)
		require.NoError(t, err)
		dSize := len(d)
		disclosureTotalSize += dSize
		fmt.Printf("  Disclosure %d (%s=%v): %d bytes\n", i+1, decoded.Key, decoded.Value, dSize)
	}

	fmt.Println()
	fmt.Printf("Issuer Signed JWT : %6d bytes (%5.1f%%)\n", issuerSize, 100*float64(issuerSize)/float64(totalSize))
	fmt.Printf("Disclosures total : %6d bytes (%5.1f%%)\n", disclosureTotalSize, 100*float64(disclosureTotalSize)/float64(totalSize))
	fmt.Printf("KB-JWT            : %6d bytes (%5.1f%%)\n", kbSize, 100*float64(kbSize)/float64(totalSize))
	fmt.Printf("Separators (~)    : %6d bytes (%5.1f%%)\n", separatorSize, 100*float64(separatorSize)/float64(totalSize))
	fmt.Printf("Total             : %6d bytes\n", totalSize)
	fmt.Println()

	// Also show passport with photo breakdown
	fmt.Println("=======================================================================")
	fmt.Println("SD-JWT VC Component Breakdown (passport with 50KB photo)")
	fmt.Println("=======================================================================")

	attrs = passportWithPhotoAttrs(50 * 1024)
	sdJwt = buildSdJwtVc(t, attrs, "benchmark.test.passport_photo", true)
	issuerJwt, disclosures, kbJwt, err = SplitSdJwtVc(sdJwt)
	require.NoError(t, err)

	totalSize = len(sdJwt)
	issuerSize = len(issuerJwt)
	kbSize = 0
	if kbJwt != nil {
		kbSize = len(*kbJwt)
	}
	separatorSize = len(disclosures) + 1

	disclosureTotalSize = 0
	photoDisclosureSize := 0
	fmt.Println()
	fmt.Println("Individual Disclosures:")
	for i, d := range disclosures {
		decoded, err := DecodeDisclosure(d)
		require.NoError(t, err)
		dSize := len(d)
		disclosureTotalSize += dSize
		if decoded.Key == "photo" {
			photoDisclosureSize = dSize
			fmt.Printf("  Disclosure %d (%s): %d bytes (%.1f KB) ** PHOTO **\n", i+1, decoded.Key, dSize, float64(dSize)/1024)
		} else {
			fmt.Printf("  Disclosure %d (%s=%v): %d bytes\n", i+1, decoded.Key, decoded.Value, dSize)
		}
	}

	nonPhotoDisclosureSize := disclosureTotalSize - photoDisclosureSize

	fmt.Println()
	fmt.Printf("Issuer Signed JWT       : %8d bytes (%5.1f%%)\n", issuerSize, 100*float64(issuerSize)/float64(totalSize))
	fmt.Printf("Photo disclosure        : %8d bytes (%5.1f%%)\n", photoDisclosureSize, 100*float64(photoDisclosureSize)/float64(totalSize))
	fmt.Printf("Other disclosures       : %8d bytes (%5.1f%%)\n", nonPhotoDisclosureSize, 100*float64(nonPhotoDisclosureSize)/float64(totalSize))
	fmt.Printf("KB-JWT                  : %8d bytes (%5.1f%%)\n", kbSize, 100*float64(kbSize)/float64(totalSize))
	fmt.Printf("Separators (~)          : %8d bytes (%5.1f%%)\n", separatorSize, 100*float64(separatorSize)/float64(totalSize))
	fmt.Printf("Total                   : %8d bytes (%.1f KB)\n", totalSize, float64(totalSize)/1024)
	fmt.Println()
}

// TestSdJwtVcSelectiveDisclosureSizes measures the size difference when only
// disclosing a subset of attributes (selective disclosure). This shows one of the
// key benefits of SD-JWT: you only send the disclosures the verifier needs.
func TestSdJwtVcSelectiveDisclosureSizes(t *testing.T) {
	fmt.Println("=======================================================================")
	fmt.Println("SD-JWT VC Selective Disclosure Size Impact")
	fmt.Println("=======================================================================")
	fmt.Println()

	attrs := passportAttrs()
	sdJwt := buildSdJwtVc(t, attrs, "pbdf.pbdf.passport", false)

	fullSize := len(sdJwt)
	fmt.Printf("Full passport credential (all %d attributes disclosed): %d bytes (%.1f KB)\n",
		len(attrs), fullSize, float64(fullSize)/1024)
	fmt.Println()

	// Test various selective disclosure scenarios using real passport attribute names
	scenarios := []struct {
		name  string
		attrs []string
	}{
		{"over18 only", []string{"over18"}},
		{"name only", []string{"firstName", "lastName"}},
		{"name + nationality", []string{"firstName", "lastName", "nationality"}},
		{"name + dateOfBirth + nationality", []string{"firstName", "lastName", "dateOfBirth", "nationality"}},
		{"all attributes", nil}, // nil means keep all
	}

	for _, scenario := range scenarios {
		var selected SdJwtVc
		var err error
		if scenario.attrs == nil {
			selected = sdJwt
		} else {
			selected, err = SelectDisclosures(sdJwt, scenario.attrs)
			require.NoError(t, err)
		}
		selectedSize := len(selected)
		fmt.Printf("  %-40s: %5d bytes (%5.1f KB, %5.1f%% of full)\n",
			scenario.name, selectedSize, float64(selectedSize)/1024,
			100*float64(selectedSize)/float64(fullSize))
	}
	fmt.Println()
}

// BenchmarkSdJwtVcIssuance benchmarks the performance of issuing SD-JWT VCs.
func BenchmarkSdJwtVcIssuance(b *testing.B) {
	profiles := []credentialProfile{
		{name: "pbdf.mobilenumber", attrs: mobilenumberAttrs()},
		{name: "gemeente.address", attrs: addressAttrs()},
		{name: "gemeente.personalData", attrs: personalDataAttrs()},
		{name: "pbdf.passport_no_photo", attrs: passportAttrs()},
		{name: "pbdf.passport_photo_15KB", attrs: passportWithPhotoAttrs(15 * 1024)},
	}

	irmaAppCert, err := utils.ParsePemCertificateChainToX5cFormat(testdata.IssuerCert_irma_app_Bytes)
	if err != nil {
		b.Fatal(err)
	}
	jwtCreator := NewEcdsaJwtCreatorWithIssuerTestkey()

	for _, profile := range profiles {
		b.Run(profile.name, func(b *testing.B) {
			for b.Loop() {
				disclosures, _ := MultipleNewDisclosureContents(profile.attrs)
				keyBinder := NewDefaultKeyBinderWithInMemoryStorage()
				holderKeys, _ := keyBinder.CreateKeyPairs(1)

				_, err := NewSdJwtVcBuilder().
					WithHolderKey(holderKeys[0]).
					WithIssuerUrl("https://openid4vc.staging.yivi.app").
					WithVerifiableCredentialType("benchmark.test."+profile.name).
					WithDisclosures(disclosures).
					WithHashingAlgorithm(HashAlg_Sha256).
					WithIssuerCertificateChain(irmaAppCert).
					WithExpiresAt(1945394126).
					WithIssuedAt(1745394126).
					Build(jwtCreator)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkSdJwtVcBatchKeyGeneration benchmarks the key pair generation for batch issuance.
func BenchmarkSdJwtVcBatchKeyGeneration(b *testing.B) {
	batchSizes := []uint{1, 10, 50, 200}

	for _, size := range batchSizes {
		b.Run(fmt.Sprintf("batch_%d", size), func(b *testing.B) {
			for b.Loop() {
				keyBinder := NewDefaultKeyBinderWithInMemoryStorage()
				_, err := keyBinder.CreateKeyPairs(size)
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
