package domain

import (
	"context"
	"errors"
	"fmt"
	twitterclone "github.com/co-codin/twitter-clone-golang"

	"golang.org/x/crypto/bcrypt"
)

var passwordCost = bcrypt.DefaultCost

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

	// check if username is already taken
	if _, err := as.UserRepo.GetByUsername(ctx, input.Username); !errors.Is(err, twitterclone.ErrNotFound) {
		return twitterclone.AuthResponse{}, twitterclone.ErrUsernameTaken
	}

	// check if email is already taken
	if _, err := as.UserRepo.GetByEmail(ctx, input.Email); !errors.Is(err, twitterclone.ErrNotFound) {
		return twitterclone.AuthResponse{}, twitterclone.ErrEmailTaken
	}

	user := twitterclone.User{
		Email:    input.Email,
		Username: input.Username,
	}

	// hash the password
	hashPassword, err := bcrypt.GenerateFromPassword([]byte(input.Password), passwordCost)
	if err != nil {
		return twitterclone.AuthResponse{}, fmt.Errorf("error hashing password: %v", err)
	}

	user.Password = string(hashPassword)

	// create the user
	user, err = as.UserRepo.Create(ctx, user)
	if err != nil {
		return twitterclone.AuthResponse{}, fmt.Errorf("error creating user: %v", err)
	}

	// return accessToken and user
	return twitterclone.AuthResponse{
		AccessToken: "a token",
		User:        user,
	}, nil
}
func (as *AuthService) Login(ctx context.Context, input twitterclone.LoginInput) (twitterclone.AuthResponse, error) {
	input.Sanitize()

	if err := input.Validate(); err != nil {
		return twitterclone.AuthResponse{}, err
	}

	user, err := as.UserRepo.GetByEmail(ctx, input.Email)
	if err != nil {
		switch {
		case errors.Is(err, twitterclone.ErrNotFound):
			return twitterclone.AuthResponse{}, twitterclone.ErrBadCredentials
		default:
			return twitterclone.AuthResponse{}, err
		}
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(input.Password)); err != nil {
		return twitterclone.AuthResponse{}, twitterclone.ErrBadCredentials
	}

	return twitterclone.AuthResponse{
		AccessToken: "a token",
		User:        user,
	}, nil
}
