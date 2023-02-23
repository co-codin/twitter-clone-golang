package domain

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/crypto/bcrypt"

	twitterclone "github.com/co-codin/twitter-clone-golang"
)

type AuthService struct {
	UserRepo twitterclone.UserRepo
}

func NewAuthService(ur twitterclone.UserRepo) *AuthService {
	return &AuthService{
		UserRepo: ur,
	}
}

func (as *AuthService) Register(ctx context.Context, input twitterclone.RegisterInput) (twitterclone.AuthResponse, error) {
	input.Sanitize()

	if err := input.Validate(); err != nil {
		return twitterclone.AuthResponse{}, err
	}

	if _, err := as.UserRepo.GetByUsername(input.Username); !errors.Is(err, twitterclone.ErrUsernameTaken) {
		return twitterclone.AuthResponse{}, twitterclone.ErrUsernameTaken
	}

	if _, err := as.UserRepo.GetByEmail(input.Email); !errors.Is(err, twitterclone.ErrEmailTaken) {
		return twitterclone.AuthResponse{}, twitterclone.ErrUsernameTaken
	}

	user := twitterclone.User{
		Email: input.Email,
		Username: input.Username,
	}

	hashPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), bcrypt.DefaultCost)

	if err != nil {
		return twitterclone.AuthResponse{}, fmt.Errorf("error hashing password: %v", err)
	}

	user.Password = string(hashPassword)

	user, err = as.UserRepo.Create(ctx, user)

	if err != nil {
		return twitterclone.AuthResponse{}, fmt.Errorf("error creating user: %v", err)
	}

	return twitterclone.AuthResponse{
		AccessToken: "a token",
		User: user,
	}, nil
}
