//go:build !dev

package main

// Пользовательская сборка: раздела разработчика и раздачи нет (см. devserver.go).

import "errors"

const devBuild = false

var errNoDev = errors.New("недоступно в этой сборке")

type DevServer struct{}

func (d *DevServer) On() bool                          { return false }
func (d *DevServer) Start() error                      { return errNoDev }
func (d *DevServer) Stop()                             {}
func (d *DevServer) Status() string                    { return "" }
func (d *DevServer) Code() (string, error)             { return "", errNoDev }
func (d *DevServer) ExportKey() (string, error)        { return "", errNoDev }
func (d *DevServer) ImportKey(string) error            { return errNoDev }
func (d *DevServer) SaveKey(string) error              { return errNoDev }
func (d *DevServer) SaveKeyToCloud() ([]string, error) { return nil, errNoDev }
func (d *DevServer) JournalText() string               { return "" }
func (d *DevServer) ClearJournal()                     {}

func CloudDirs() []string { return nil }

func (a *App) devUnlock(string) error   { return errNoDev }
func (a *App) devLock()                 {}
func (a *App) devSetShare(bool) error   { return errNoDev }
func (a *App) devInit()                 {}
func (a *App) devStop()                 {}
func (a *App) devState() map[string]any { return map[string]any{"build": false} }
