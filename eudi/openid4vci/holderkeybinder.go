package openid4vci

import "github.com/privacybydesign/irmago/eudi/services"

// HolderKeyBinder is services.HolderKeyBinder, kept under its old name for one
// release so external implementations (a WSCA adapter) keep compiling. The
// interface moved because the per-format registry that carries it lives in
// services, which this package imports.
type HolderKeyBinder = services.HolderKeyBinder
