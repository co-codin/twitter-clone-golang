package domain

import (
	"context"
	"errors"
	twitterclone "github.com/co-codin/twitter-clone-golang"
	"github.com/co-codin/twitter-clone-golang/mocks"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestAuthService_Register(t *testing.T) {
	validInput := twitterclone.RegisterInput{
		Username:        "bob",
		Email:           "bob@example.com",
		Password:        "password",
		ConfirmPassword: "password",
	}

	t.Run("can register", func(t *testing.T) {
		ctx := context.Background()

		userRepo := &mocks.UserRepo{}

		userRepo.On("GetByUsername", mock.Anything, mock.Anything).
			Return(twitterclone.User{}, twitterclone.ErrNotFound)

		userRepo.On("GetByEmail", mock.Anything, mock.Anything).
			Return(twitterclone.User{}, twitterclone.ErrNotFound)

		userRepo.On("Create", mock.Anything, mock.Anything).
			Return(twitterclone.User{
				ID:       "123",
				Username: validInput.Username,
				Email:    validInput.Email,
			}, nil)

		service := NewAuthService(userRepo)

		res, err := service.Register(ctx, validInput)

		require.NoError(t, err)

		require.NotEmpty(t, res.AccessToken)
		require.NotEmpty(t, res.User.ID)
		require.NotEmpty(t, res.User.Email)
		require.NotEmpty(t, res.User.Username)

		userRepo.AssertExpectations(t)
	})

	t.Run("username taken", func(t *testing.T) {
		ctx := context.Background()

		userRepo := &mocks.UserRepo{}

		userRepo.On("GetByUsername", mock.Anything, mock.Anything).
			Return(twitterclone.User{}, nil)

		service := NewAuthService(userRepo)

		_, err := service.Register(ctx, validInput)
		require.ErrorIs(t, err, twitterclone.ErrUsernameTaken)

		userRepo.AssertNotCalled(t, "Create")

		userRepo.AssertExpectations(t)
	})

	t.Run("email taken", func(t *testing.T) {
		ctx := context.Background()

		userRepo := &mocks.UserRepo{}

		userRepo.On("GetByUsername", mock.Anything, mock.Anything).
			Return(twitterclone.User{}, twitterclone.ErrNotFound)

		userRepo.On("GetByEmail", mock.Anything, mock.Anything).
			Return(twitterclone.User{}, nil)

		service := NewAuthService(userRepo)

		_, err := service.Register(ctx, validInput)
		require.ErrorIs(t, err, twitterclone.ErrEmailTaken)

		userRepo.AssertNotCalled(t, "Create")

		userRepo.AssertExpectations(t)
	})

	t.Run("create error", func(t *testing.T) {
		ctx := context.Background()

		userRepo := &mocks.UserRepo{}

		userRepo.On("GetByUsername", mock.Anything, mock.Anything).
			Return(twitterclone.User{}, twitterclone.ErrNotFound)

		userRepo.On("GetByEmail", mock.Anything, mock.Anything).
			Return(twitterclone.User{}, twitterclone.ErrNotFound)

		userRepo.On("Create", mock.Anything, mock.Anything).
			Return(twitterclone.User{}, errors.New("something"))

		service := NewAuthService(userRepo)

		_, err := service.Register(ctx, validInput)
		require.Error(t, err)

		userRepo.AssertExpectations(t)
	})

	t.Run("invalid input", func(t *testing.T) {
		ctx := context.Background()

		userRepo := &mocks.UserRepo{}

		service := NewAuthService(userRepo)

		_, err := service.Register(ctx, twitterclone.RegisterInput{})
		require.ErrorIs(t, err, twitterclone.ErrValidation)

		userRepo.AssertNotCalled(t, "GetByUsername")
		userRepo.AssertNotCalled(t, "GetByEmail")
		userRepo.AssertNotCalled(t, "Create")

		userRepo.AssertExpectations(t)
	})
}

func TestAuthService_Login(t *testing.T) {
	validInput := twitterclone.LoginInput{
		Email:    "bob@gmail.com",
		Password: "password",
	}

	t.Run("can login", func(t *testing.T) {
		ctx := context.Background()

		userRepo := &mocks.UserRepo{}

		userRepo.On("GetByEmail", mock.Anything, mock.Anything).
			Return(twitterclone.User{
				Email:    validInput.Email,
				Password: validInput.Password,
			}, nil)

		service := NewAuthService(userRepo)

		_, err := service.Login(ctx, validInput)
		require.NoError(t, err)

		userRepo.AssertExpectations(t)
	})

	t.Run("wrong password", func(t *testing.T) {
		ctx := context.Background()

		userRepo := &mocks.UserRepo{}

		userRepo.On("GetByEmail", mock.Anything, mock.Anything).
			Return(twitterclone.User{
				Email:    validInput.Email,
				Password: "test_password",
			}, nil)

		service := NewAuthService(userRepo)

		validInput.Password = "somethingelse"

		_, err := service.Login(ctx, validInput)
		require.ErrorIs(t, err, twitterclone.ErrBadCredentials)

		userRepo.AssertExpectations(t)
	})

	t.Run("email not found", func(t *testing.T) {
		ctx := context.Background()

		userRepo := &mocks.UserRepo{}

		userRepo.On("GetByEmail", mock.Anything, mock.Anything).
			Return(twitterclone.User{}, twitterclone.ErrNotFound)

		service := NewAuthService(userRepo)

		_, err := service.Login(ctx, validInput)
		require.ErrorIs(t, err, twitterclone.ErrBadCredentials)

		userRepo.AssertExpectations(t)
	})

	t.Run("get user by email error", func(t *testing.T) {
		ctx := context.Background()

		userRepo := &mocks.UserRepo{}

		userRepo.On("GetByEmail", mock.Anything, mock.Anything).
			Return(twitterclone.User{}, errors.New("something"))

		service := NewAuthService(userRepo)

		_, err := service.Login(ctx, validInput)
		require.Error(t, err)

		userRepo.AssertExpectations(t)
	})

	t.Run("invalid input", func(t *testing.T) {
		ctx := context.Background()

		userRepo := &mocks.UserRepo{}

		service := NewAuthService(userRepo)

		_, err := service.Login(ctx, twitterclone.LoginInput{
			Email:    "bob",
			Password: "",
		})
		require.ErrorIs(t, err, twitterclone.ErrValidation)

		userRepo.AssertExpectations(t)
	})
}
