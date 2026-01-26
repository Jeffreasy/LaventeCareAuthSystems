package main

import (
	"context"
	"fmt"
	"log"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	url := "postgres://user:password@localhost:5488/laventecare?sslmode=disable"
	pool, err := pgxpool.New(context.Background(), url)
	if err != nil {
		log.Fatal(err)
	}
	defer pool.Close()

	rows, err := pool.Query(context.Background(), "SELECT column_name FROM information_schema.columns WHERE table_name = 'users'")
	if err != nil {
		log.Fatal(err)
	}
	defer rows.Close()

	fmt.Println("Columns in users table:")
	for rows.Next() {
		var col string
		rows.Scan(&col)
		fmt.Println("- " + col)
	}
}
