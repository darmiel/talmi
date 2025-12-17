package cmd

import (
	"fmt"
	"time"

	"github.com/davecgh/go-spew/spew"
	"github.com/golang-jwt/jwt/v5"
	"github.com/rs/zerolog/log"
	"github.com/spf13/cobra"
)

var attributesCmd = &cobra.Command{
	Use:   "attributes",
	Short: "Prints the attributes (claims) of a JWT token",
	Long: `The attributes command extracts and displays the claims from a provided JWT token.
It does not perform any validation, it simply decodes the token and shows its contents.`,
	Example: `  talmi attributes <JWT token>`,
	Args:    cobra.ExactArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		tokenInput := args[0]
		if tokenInput == "" {
			return fmt.Errorf("token cannot be empty")
		}

		parser := jwt.NewParser()
		token, _, err := parser.ParseUnverified(tokenInput, jwt.MapClaims{})
		if err != nil {
			return fmt.Errorf("parsing token: %w", err)
		}
		claims, ok := token.Claims.(jwt.MapClaims)
		if !ok {
			return fmt.Errorf("invalid token claims")
		}

		log.Info().Msg("Token Claims:")
		log.Info().Msg(spew.Sdump(claims))

		if issRaw, ok := claims["iss"]; ok {
			log.Info().Msgf("Issuer (iss): %v", issRaw)
		} else {
			log.Warn().Msg("Token does not contain 'iss' claim")
		}

		if audRaw, ok := claims["aud"]; ok {
			log.Info().Msgf("Audience (aud): %v", audRaw)
		}

		// print & parse expiration if present and print remaining
		if expRaw, ok := claims["exp"]; ok {
			if expFloat, ok := expRaw.(float64); ok {
				expInt := int64(expFloat)
				expTime := time.Unix(expInt, 0)
				remaining := time.Until(expTime)
				log.Info().Msgf("Expiration (exp): %v (in %v)", expTime, remaining)
			}
		}

		return nil
	},
}

func init() {
	rootCmd.AddCommand(attributesCmd)
}
