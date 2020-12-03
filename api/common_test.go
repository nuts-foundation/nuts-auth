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

package api

import (
    "testing"

    "github.com/golang/mock/gomock"
    "github.com/nuts-foundation/nuts-auth/mock"
    servicesMock "github.com/nuts-foundation/nuts-auth/mock/services"
    coreMock "github.com/nuts-foundation/nuts-go-core/mock"
)

type TestContext struct {
    ctrl         *gomock.Controller
    echoMock     *coreMock.MockContext
    authMock     *mock.MockAuthClient
    oauthMock    *servicesMock.MockOAuthClient
    notaryMock   *servicesMock.MockContractNotary
    contractMock *servicesMock.MockContractClient
    wrapper      Wrapper
}

type mockAuthClient struct {
    ctrl               gomock.Controller
    mockContractClient *servicesMock.MockContractClient
    mockContractNotary *servicesMock.MockContractNotary
}

var createContext = func(t *testing.T) *TestContext {
    ctrl := gomock.NewController(t)
    authMock := mock.NewMockAuthClient(ctrl)
    oauthMock := servicesMock.NewMockOAuthClient(ctrl)
    notaryMock := servicesMock.NewMockContractNotary(ctrl)
    contractMock := servicesMock.NewMockContractClient(ctrl)

    authMock.EXPECT().OAuthClient().AnyTimes().Return(oauthMock)
    authMock.EXPECT().ContractClient().AnyTimes().Return(contractMock)
    authMock.EXPECT().ContractNotary().AnyTimes().Return(notaryMock)

    return &TestContext{
        ctrl:         ctrl,
        echoMock:     coreMock.NewMockContext(ctrl),
        authMock:     authMock,
        oauthMock:    oauthMock,
        contractMock: contractMock,
        notaryMock:   notaryMock,
        wrapper:      Wrapper{Auth: authMock},
    }
}
