package main

type trustAnchorMetadata struct {
	Name     string
	Operator string
	SHA256   string
}

func (a AnchorID) Metadata() trustAnchorMetadata {
	return trustAnchorMetadataByOID[a.RelativeOID]
}

// trustAnchorMetadataByOID is derived from Chromium's Chrome Root Store
// root_store.textproto. Trust Anchor IDs are globally scoped beneath the
// assignee's Private Enterprise Number, so the same identifier denotes the
// same trust anchor when advertised by another implementation.
var trustAnchorMetadataByOID = map[string]trustAnchorMetadata{
	"52580.200109.1.7":  {Name: "QuoVadis Root CA 2 G3", Operator: "QuoVadis / DigiCert", SHA256: "8fe4fb0af93a4d0d67db0bebb23e37c71bf325dcbcdd240ea04daf58b47e1840"},
	"52580.200109.1.8":  {Name: "QuoVadis Root CA 3 G3", Operator: "QuoVadis / DigiCert", SHA256: "88ef81de202eb018452e43f864725cea5fbd1fc2d9d205730709c5d8b8690f46"},
	"52580.200109.1.9":  {Name: "DigiCert Global Root G2", Operator: "DigiCert", SHA256: "cb3ccbb76031e5e0138f8dd39a23f9de47ffc35e43c1144cea27d46a5ab1cb5f"},
	"52580.200109.1.10": {Name: "DigiCert Global Root G3", Operator: "DigiCert", SHA256: "31ad6648f8104138c738f39ea4320133393e3a18cc02296ef97c2ac9ef6731d0"},
	"52580.200109.1.11": {Name: "DigiCert Trusted Root G4", Operator: "DigiCert", SHA256: "552f7bdcf1a7af9e6ce672017f4f12abf77240c78e761ac203d1d9d20ac89988"},
	"52580.200109.1.12": {Name: "DigiCert Assured ID Root G2", Operator: "DigiCert", SHA256: "7d05ebb682339f8c9451ee094eebfefa7953a114edb2f44949452fab7d2fc185"},
	"52580.200109.1.13": {Name: "DigiCert Assured ID Root G3", Operator: "DigiCert", SHA256: "7e37cb8b4c47090cab36551ba6f45db840680fba166a952db100717f43053fc2"},
	"52580.200109.1.18": {Name: "DigiCert TLS RSA4096 Root G5", Operator: "DigiCert", SHA256: "371a00dc0533b3721a7eeb40e8419e70799d2b0a0f2c1d80693165f7cec4ad75"},
	"52580.200109.1.19": {Name: "DigiCert TLS ECC P384 Root G5", Operator: "DigiCert", SHA256: "018e13f0772532cf809bd1b17281867283fc48c6e13be9c69812854a490c1b05"},

	"11129.9.1":  {Name: "GTS Root R1", Operator: "Google Trust Services", SHA256: "d947432abde7b7fa90fc2e6b59101b1280e0e1c7e4e40fa3c6887fff57a7f4cf"},
	"11129.9.2":  {Name: "GTS Root R2", Operator: "Google Trust Services", SHA256: "8d25cd97229dbf70356bda4eb3cc734031e24cf00fafcfd32dc76eb5841c7ea8"},
	"11129.9.3":  {Name: "GTS Root R3", Operator: "Google Trust Services", SHA256: "34d8a73ee208d9bcdb0d956520934b4e40e69482596e8b6f73c8426b010a6f48"},
	"11129.9.4":  {Name: "GTS Root R4", Operator: "Google Trust Services", SHA256: "349dfa4058c5e263123b398ae795573c4e1313c83fe68f93556cd5e8031b3c7d"},
	"11129.9.5":  {Name: "WR1", Operator: "Google Trust Services", SHA256: "b10b6f00e609509e8700f6d34687a2bfce38ea05a8fdf1cdc40c3a2a0d0d0e45"},
	"11129.9.6":  {Name: "WR2", Operator: "Google Trust Services", SHA256: "e6fe22bf45e4f0d3b85c59e02c0f495418e1eb8d3210f788d48cd5e1cb547cd4"},
	"11129.9.7":  {Name: "WR3", Operator: "Google Trust Services", SHA256: "2fe357db13751ff9160e87354975b3407498f41c9bd16a48657866e6e5a9b4c7"},
	"11129.9.8":  {Name: "WR4", Operator: "Google Trust Services", SHA256: "dc9416c2f855126d6de977677538f2f967ff4998e90dfa435a17219be077fc06"},
	"11129.9.9":  {Name: "WR5", Operator: "Google Trust Services", SHA256: "ae0fc852280f1b87cedaf73cfb84cf106efec88e8294253af352ed4034460d7b"},
	"11129.9.10": {Name: "WE1", Operator: "Google Trust Services", SHA256: "1dfc1605fbad358d8bc844f76d15203fac9ca5c1a79fd4857ffaf2864fbebf96"},
	"11129.9.11": {Name: "WE2", Operator: "Google Trust Services", SHA256: "9c3f2fd11c57d7c649ad5a0932c0f0d29756f6a0a1c74c43e1e89a62d64cd320"},
	"11129.9.12": {Name: "WE3", Operator: "Google Trust Services", SHA256: "9f819a4c876e12dc84e6fe0e37c1a69b137094b453fa98449398f4b71f4d0092"},
	"11129.9.13": {Name: "WE4", Operator: "Google Trust Services", SHA256: "d0c97e56c7b0ba812d944ad771f7799b5d4144a2327a4e416554f7ee2aa0aeae"},
	"11129.9.14": {Name: "WE5", Operator: "Google Trust Services", SHA256: "847409e63526f162753ac49f75218efaafa7d5c94ade9095ce72e7f6b6e3ac99"},
	"11129.9.15": {Name: "AE1", Operator: "Google Trust Services", SHA256: "812c212e9e45dc5005c7f47411183f5fb2ff1baee184d3354b2e93d78c280164"},

	"44947.2.1":  {Name: "ISRG Root X1", Operator: "Internet Security Research Group / Let's Encrypt", SHA256: "96bcec06264976f37460779acf28c5a7cfe8a3c0aae11a8ffcee05c0bddf08c6"},
	"44947.2.6":  {Name: "ISRG Root X2", Operator: "Internet Security Research Group / Let's Encrypt", SHA256: "69729b8e15a86efc177a57afb7171dfc64add28c2fca8cf1507e34453ccb1470"},
	"44947.2.13": {Name: "E7", Operator: "Let's Encrypt", SHA256: "54715420224c5b65beed018dc3940d7338c577e322d5488f633d8c6a8fed61b2"},
	"44947.2.14": {Name: "E8", Operator: "Let's Encrypt", SHA256: "ac1274542267f17b525535b5563bf731febb182533b46a82dc869cb64eb528c0"},
	"44947.2.15": {Name: "E9", Operator: "Let's Encrypt", SHA256: "4185df97806c2ba76f1d79823f112ffa639a49ccdc990908102067ab6412b886"},
	"44947.2.18": {Name: "R12", Operator: "Let's Encrypt", SHA256: "131fce7784016899a5a00203a9efc80f18ebbd75580717edc1553580930836ec"},
	"44947.2.19": {Name: "R13", Operator: "Let's Encrypt", SHA256: "d3b128216a843f8ef1321501f5df52a5df52939ee2c19297712cd3de4d419354"},
	"44947.2.20": {Name: "R14", Operator: "Let's Encrypt", SHA256: "24d45aa9b8d6053d281f3842c8cc0c6c1af7ccdfd42dd5c12f6a74fa9323f7a2"},
}
