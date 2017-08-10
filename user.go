package authenticator

type User struct {
	ID       int    `json:"id"`
	Username string `json:"username"`
	Password string `json:"password"`
	//	Type     string `json:"type"`
}

func (u *User) valid(eu *User) bool {
	// check password and return true if good
	if u.Username == eu.Username && u.Password == eu.Password {
		return true
	}

	return false
}
