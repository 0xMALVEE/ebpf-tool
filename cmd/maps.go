package cmd

import (
	"strconv"
	"tui-bpftool/internal/bpf"

	"github.com/rivo/tview"
)

func GetMapsView(app *Application) *tview.Flex {
	programId := app.SelectedProgramID

	button := tview.NewButton("Back").SetSelectedFunc(func() {
		app.SetCurrentView(func() {
			app.CurrentView = ProgramListView
			app.App.SetRoot(app.ProgListView, true)
		})
	})

	maps, err := bpf.GetAllMaps(programId)

	// Build map details string
	var mapsInfo string
	mapsInfo = "Program ID: " + strconv.Itoa(int(programId)) + "\n"
	if err != nil {
		mapsInfo += "Error getting maps: " + err.Error() + "\n"
	}
	mapsInfo += "Total Maps: " + strconv.Itoa(len(maps)) + "\n\n"

	for i, m := range maps {
		mapsInfo += "=== Map " + strconv.Itoa(i+1) + " ===\n"
		mapsInfo += "Type: " + m.Type().String() + "\n"
		mapsInfo += "FD: " + strconv.Itoa(m.FD()) + "\n"

		// Get map info for additional details
		info, err := m.Info()
		if err == nil {
			mapsInfo += "Name: " + info.Name + "\n"
			if id, ok := info.ID(); ok {
				mapsInfo += "ID: " + strconv.Itoa(int(id)) + "\n"
			}
			mapsInfo += "Key Size: " + strconv.Itoa(int(info.KeySize)) + " bytes\n"
			mapsInfo += "Value Size: " + strconv.Itoa(int(info.ValueSize)) + " bytes\n"
			mapsInfo += "Max Entries: " + strconv.Itoa(int(info.MaxEntries)) + "\n"
		}
		mapsInfo += "\n"
	}

	textView := tview.NewTextArea().SetText(mapsInfo, false)

	layout := tview.NewFlex().SetDirection(tview.FlexRow).
		AddItem(button, 1, 0, false).
		AddItem(textView, 0, 1, false)

	return layout
}
