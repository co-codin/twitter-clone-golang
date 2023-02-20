package twitterclone

import (
	"context"
	"fmt"
	"regexp"
	"strings"
)

var (
	UsernameMinLength = 2
	PasswordMinLength = 4
)

var emailRegexp = regexp.MustCompile("^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$")


type AuthService interface {
	Register(ctx context.Context, input RegisterInput) (AuthResponse, error)
}

type AuthResponse struct {
	AccessToken string
	User User
}

type RegisterInput struct {
	Email string
	Username string
	Password string
	ConfirmPassword string
}

func (input *RegisterInput) Sanitize() {
	input.Email = strings.TrimSpace(input.Email)
	input.Email = strings.ToLower(input.Email)

	input.Username = strings.TrimSpace(input.Username)
}

func (input RegisterInput) Validate() error {
	if len(input.Username) < UsernameMinLength {
		return fmt.Errorf("%w: username not long enough, (%d) characters at least", ErrValidation, UsernameMinLength)
	}

	if !emailRegexp.MatchString(input.Email) {
		return fmt.Errorf("%w: email not valid", ErrValidation)
	}

	if len(input.Password) < PasswordMinLength {
		return fmt.Errorf("%w: password not long enough, (%d) characters at least", ErrValidation, PasswordMinLength)
	}

	if input.Password != input.ConfirmPassword {
		return fmt.Errorf("%w: confirm password must match the password", ErrValidation)
	}

	return nil
}