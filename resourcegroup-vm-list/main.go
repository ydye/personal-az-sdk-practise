package main

import (
	colorable "github.com/mattn/go-colorable"
	"github.com/sirupsen/logrus"
	"github.com/ydye/personal-az-sdk-practise/resourcegroup-vm-list/cmd"
)

func main() {
	logrus.SetFormatter(&logrus.TextFormatter{ForceColors: true})
	logrus.SetOutput(colorable.NewColorableStdout())

}
