/*
 * Nuts auth
 * Copyright (C) 2020. Nuts community
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package pkg

import "time"

// JwtBearerGrantType defines the grant-type to use in the access token request
const JwtBearerGrantType = "urn:ietf:params:oauth:grant-type:jwt-bearer"

// AuthConfig holds all the configuration params
type AuthConfig struct {
	Mode string
	// Address to bind the http server to. Default localhost:1323
	Address                   string
	PublicUrl                 string
	IrmaConfigPath            string
	IrmaSchemeManager         string
	SkipAutoUpdateIrmaSchemas bool
	ActingPartyCn             string
	EnableCORS                bool
	ContractValidators        []string
	ContractValidDuration     time.Duration
}
