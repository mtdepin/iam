package logger

import "fmt"

func Error(msg string, data ...interface{}) {
	fmt.Println(msg)
}

func Info(msg string, data ...interface{}) {
	fmt.Println(msg)
}
func FatalIf(msg string, data ...interface{}) {
	fmt.Println(msg)
}
