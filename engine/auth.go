package engine

import (
	"fmt"

	"github.com/playwright-community/playwright-go"
)

func Login(ctx playwright.BrowserContext, loginURL, user, pass, userSel, passSel, submitSel string) bool {
	page, _ := ctx.NewPage()
	defer page.Close()

	if _, err := page.Goto(loginURL); err != nil {
		fmt.Printf("[!] Failed to load login page: %v\n", err)
		return false
	}

	userSelectors := []string{"input[name='user']", "input[name='username']", "input[type='email']", "#username"}
	if userSel != "" {
		userSelectors = append([]string{userSel}, userSelectors...) // user-provided takes priority
	}

	passSelectors := []string{"input[name='pass']", "input[name='password']", "input[type='password']", "#password"}
	if passSel != "" {
		passSelectors = append([]string{passSel}, passSelectors...)
	}

	submitSelectors := []string{"button[type='submit'], input[type='submit'], .login-btn"}
	if submitSel != "" {
		submitSelectors = append([]string{submitSel}, submitSelectors...)
	}

	// fill username
	filledUser := false
	for _, sel := range userSelectors {
		if err := page.Fill(sel, user); err == nil {
			filledUser = true
			break
		}
	}
	if !filledUser {
		fmt.Println("[!] Warning: no username field matched any known selector")
	}

	// fill password
	filledPass := false
	for _, sel := range passSelectors {
		if err := page.Fill(sel, pass); err == nil {
			filledPass = true
			break
		}
	}
	if !filledPass {
		fmt.Println("[!] Warning: no password field matched any known selector")
	}

	// submit
	if _, err := page.ExpectNavigation(func() error {
		for _, sel := range submitSelectors {
			if err := page.Click(sel); err == nil {
				return nil
			}
		}
		return fmt.Errorf("no submit selector matched")
	}); err != nil {
		fmt.Printf("[!] Navigation failed after login: %v\n", err)
		return false
	}

	_, err := page.WaitForSelector(".user-avatar, #dashboard, [data-user-id]",
		playwright.PageWaitForSelectorOptions{
			Timeout: playwright.Float(5000),
		})
	if err != nil {
		fmt.Println("[!] Login may have failed — no post-login element found")
		return false
	}

	fmt.Println("[+] Login successful.")
	return true
}
