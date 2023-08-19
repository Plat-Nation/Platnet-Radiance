package main

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/golang-jwt/jwt"
	"github.com/guregu/dynamo"
	"golang.org/x/crypto/bcrypt"
)

const DB_NAME = "radiance-users"

var (
	verifyKey *rsa.PublicKey
	signKey   *rsa.PrivateKey
)

type user struct {
	Username string `dynamo:"username"`
	Hash     string `dynamo:"hash"`
	Role     string `dynamo:"role"`
	Active   bool   `dynamo:"active"`
}

type signup struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Confirm  string `json:"confirm-password"`
}

type userJwt struct {
	*jwt.StandardClaims
	User string
	Role string
}

func main() {

	//Get RSA keys for signing and verifying JWTs
	pbk, err := ioutil.ReadFile(".keys/jwt256.pub")
	if err != nil {
		panic(err)
	}

	pvk, err := ioutil.ReadFile(".keys/jwt256")
	if err != nil {
		panic(err)
	}

	verifyKey, err = jwt.ParseRSAPublicKeyFromPEM(pbk)
	if err != nil {
		panic(err)
	}
	signKey, err = jwt.ParseRSAPrivateKeyFromPEM(pvk)
	if err != nil {
		panic(err)
	}

	//Router
	http.HandleFunc("/", mainHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/logout", logoutHandler)
	http.HandleFunc("/user", userHandler)

	err = http.ListenAndServe(":8080", nil)
	if err != nil {
		panic(err)
	}
}

func hashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func checkPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(password), []byte(hash))
	return err == nil
}

func createJwt(user string, role string, hoursToExpiration int) (*string, error) {
	t := jwt.New(jwt.GetSigningMethod("RS256"))

	t.Claims = &userJwt{
		&jwt.StandardClaims{
			IssuedAt:  time.Now().Unix(),
			ExpiresAt: time.Now().Add(time.Hour * time.Duration(hoursToExpiration)).Unix(),
		},
		user,
		role,
	}

	res, err := t.SignedString(signKey)

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return &res, nil
}

func verifyAndDecodeJwt(t string) (*jwt.Token, error) {
	token, err := jwt.Parse(t, func(token *jwt.Token) (interface{}, error) {
		return verifyKey, nil
	})

	if err != nil {
		fmt.Println(err)
		return nil, err
	} else if !token.Valid {
		fmt.Println(err)
		return nil, nil
	}

	return token, nil
}

func deleteUser(u user) error {
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region:      aws.String("us-east-1"),
			Credentials: credentials.NewStaticCredentials(os.Getenv("ACCESS_KEY"), os.Getenv("SECRET_ACCESS_KEY"), ""),
		},
	})
	if err != nil {
		fmt.Println(err)
		return err
	}

	db := dynamo.New(sess)
	table := db.Table(DB_NAME)

	u.Active = false
	err = table.Put(u).Run()
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func getUser(username string) (*user, error) {
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region:      aws.String("us-east-1"),
			Credentials: credentials.NewStaticCredentials(os.Getenv("ACCESS_KEY"), os.Getenv("SECRET_ACCESS_KEY"), ""),
		},
	})
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	db := dynamo.New(sess)
	table := db.Table(DB_NAME)

	var u user
	err = table.Get("username", username).One(&u)
	fmt.Println("Input: ", username)
	fmt.Println("Username: ", u.Username)
	if err != nil {
		return nil, err
	}

	return &u, nil

}

func saveUser(u user) error {
	sess, err := session.NewSessionWithOptions(session.Options{
		Config: aws.Config{
			Region:      aws.String("us-east-1"),
			Credentials: credentials.NewStaticCredentials(os.Getenv("ACCESS_KEY"), os.Getenv("SECRET_ACCESS_KEY"), ""),
		},
	})
	if err != nil {
		fmt.Println(err)
		return err
	}

	db := dynamo.New(sess)
	table := db.Table(DB_NAME)

	err = table.Put(u).Run()
	if err != nil {
		fmt.Println(err)
		return err
	}
	return nil
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		inputUser := r.URL.Query().Get("user")
		inputPass := r.URL.Query().Get("password")
		//Later I could add an option for stayLoggedIn which would change the 8 hour expiration in the JWT to longer

		user, err := getUser(inputUser)
		if err != nil || user == nil {

			//TODO: Check that attempts to login with a user that doesn't exist fail here
			http.Error(w, "Incorrect username or password", http.StatusForbidden)
			fmt.Println(&user)
			fmt.Println(err)
			return
		}

		if !user.Active {
			http.Error(w, "User no longer exists", http.StatusForbidden)
			return
			//The below uses the password, not password hash, because checkPasswordHash take in (hash, passwordString)
		} else if !checkPasswordHash(user.Hash, inputPass) {
			http.Error(w, "Incorrect username or password", http.StatusForbidden)
			return
		} else {
			t, err := createJwt(user.Username, user.Role, 8)
			if err != nil {
				http.Error(w, "Error generating JWT", http.StatusInternalServerError)
				fmt.Println(err)
				return
			}

			cookie := http.Cookie{
				Name:     "jwt",
				Value:    *t,
				HttpOnly: true,
				Secure:   true,
			}
			http.SetCookie(w, &cookie)
			http.Redirect(w, r, "/", http.StatusFound)
			return
		}
	default:
		http.NotFound(w, r)
	}
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		deleteCookie := http.Cookie{
			Name:    "jwt",
			Value:   "",
			Expires: time.Unix(0, 0),
		}
		http.SetCookie(w, &deleteCookie)
		w.WriteHeader(http.StatusFound)
		fmt.Fprintln(w, "Logged out successfully")
		return
	default:
		http.NotFound(w, r)
		return
	}
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		t, err := r.Cookie("jwt")

		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		decodedToken, err := verifyAndDecodeJwt(t.Value)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(err)
			return
		}

		if !decodedToken.Valid {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "You are logged in")

	default:
		http.NotFound(w, r)
		return
	}
}

func userHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		t, err := r.Cookie("jwt")

		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		inputUser := r.URL.Query().Get("user")

		decodedJwt, err := verifyAndDecodeJwt(t.Value)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(err)
			return
		} else if !decodedJwt.Valid {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		claims := decodedJwt.Claims.(jwt.MapClaims)
		username := claims["User"].(string)

		if inputUser != username {
			http.Error(w, "You can only view your own user page", http.StatusForbidden)
			return
		}

		//Get user info from DB
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "You are logged in as %s\n", username)

	case http.MethodDelete:
		t, err := r.Cookie("jwt")

		if err != nil {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}

		inputUser := r.URL.Query().Get("user")

		decodedJwt, err := verifyAndDecodeJwt(t.Value)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(err)
			return
		} else if !decodedJwt.Valid {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		claims := decodedJwt.Claims.(jwt.MapClaims)
		username := claims["User"].(string)

		if inputUser != username {
			http.Error(w, "Access Forbidden", http.StatusForbidden)
			return
		}

		u, err := getUser(username)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			fmt.Println(err)
			return
		}

		err = deleteUser(*u)
		if err != nil {
			http.Error(w, "Error deleting user", http.StatusInternalServerError)
			fmt.Println(err)
			return
		}

		w.WriteHeader(http.StatusCreated)
		fmt.Fprintln(w, "User deleted successfully")
	case http.MethodPost:
		var signup signup

		err := json.NewDecoder(r.Body).Decode(&signup)
		if err != nil {
			http.Error(w, "Error parsing request", http.StatusInternalServerError)
			fmt.Println(err)
			return
		}
		defer r.Body.Close()

		conflict, _ := getUser(signup.User)

		if signup.Password != signup.Confirm {
			http.Error(w, "Passwords do not match", http.StatusInternalServerError)
			return
		} else if conflict != nil {
			http.Error(w, "Please choose a different username", http.StatusConflict)
			return
		} else {
			h, err := hashPassword(signup.Password)
			if err != nil {
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
				fmt.Println(err)
				return
			}

			u := user{
				Username: signup.User,
				Hash:     h,
				Role:     "user",
				Active:   true,
			}

			err = saveUser(u)
			if err != nil {
				http.Error(w, "Error creating user", http.StatusInternalServerError)
				fmt.Println(err)
				return
			}

			w.WriteHeader(http.StatusCreated)
			fmt.Fprintln(w, "User created successfully")
		}
	}
}
