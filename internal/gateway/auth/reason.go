package auth

import (
	"errors"
	"fmt"
)

// DenyCode identifies the exact grammar violation, refusal rule, or auth
// rejection code from PROTOCOL §2.1, §2.2, §1.28, and §6.1.
type DenyCode string

const (
	// Priority steps 1-7 from PROTOCOL §1.28:
	CodeUsernameControl   DenyCode = "E_USERNAME_CONTROL"    // errdict:internal
	CodeUsernameNonASCII  DenyCode = "E_USERNAME_NON_ASCII"  // errdict:internal
	CodeUsernameColon     DenyCode = "E_USERNAME_COLON"      // errdict:internal
	CodeUsernameEmptyPart DenyCode = "E_USERNAME_EMPTY_PART" // errdict:internal
	CodeUsernameLength    DenyCode = "E_USERNAME_LENGTH"     // errdict:internal
	CodeNameReserved      DenyCode = "E_NAME_RESERVED"       // errdict:internal
	CodeUsernameGrammar   DenyCode = "E_USERNAME_GRAMMAR"    // errdict:internal
)

// UsernameError is a typed error returned when username parsing fails.
type UsernameError struct {
	Code    DenyCode
	Message string
}

func (e *UsernameError) Error() string {
	return fmt.Sprintf("auth: %s: %s", e.Code, e.Message)
}

// ErrorDenyCode extracts the DenyCode if err is or wraps a *UsernameError.
func ErrorDenyCode(err error) DenyCode {
	var ue *UsernameError
	if errors.As(err, &ue) && ue != nil {
		return ue.Code
	}
	return ""
}
