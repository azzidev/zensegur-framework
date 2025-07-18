package zensegur

/*
type User struct {
	ID       string    `bson:"_id,omitempty" json:"id,omitempty"`
	Username string    `bson:"username" json:"username"`
	Email    string    `bson:"email" json:"email"`
	BaseDocument
}

func ExampleUsage() {
	ctx := context.Background()
	client, err := NewClient(ctx, "mongodb://localhost:27017", "zensegur")
	if err != nil {
		panic(err)
	}
	defer client.Close()

	cache := NewCache(5 * time.Minute)

	clientWithContext := client.
		WithTenant("empresa1").
		WithAuthor("user123", "João Silva").
		WithAudit(true).
		WithCache(cache)

	userRepo := clientWithContext.RepositoryFor[User]("users")

	user := User{
		Username: "joao.silva",
		Email:    "joao@example.com",
	}

	err = userRepo.Insert(ctx, &user)

	filter := map[string]interface{}{
		"username": "joao.silva",
	}

	foundUser := userRepo.GetFirst(ctx, filter)

	allUsers := userRepo.GetAll(ctx, map[string]interface{}{})

	updateFields := map[string]interface{}{
		"email": "joao.novo@example.com",
	}
	err = userRepo.Update(ctx, filter, updateFields)

	err = userRepo.Delete(ctx, filter)
}
*/
