package main

import (
	"tui-bpftool/cmd"
)

func main() {

	app := cmd.Application{CurrentView: cmd.ProgramListView}
	app.NewApplication()

	// set the views
	app.ProgListView = cmd.GetProgListView(&app)
	app.MapsView = cmd.GetMapsView(&app)

	if err := app.App.SetRoot(app.ProgListView, true).Run(); err != nil {
		panic(err)
	}
}
