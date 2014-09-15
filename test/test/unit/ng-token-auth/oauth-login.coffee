suite 'oauth2 login', ->
  dfd = null

  suite 'using postMessage', ->
    popupWindow =
      closed: false
      postMessage: ->

    setup ->
      # disable popup behavior
      $window.open = -> popupWindow

      # verify that popup was initiated
      sinon.spy($window, 'open')

    suite 'using config options', ->
      test 'optional params are sent', ->
        expectedAuthUrl = $auth.apiUrl() +
          $auth.getConfig().authProviderPaths['github'] +
          '?auth_origin_url=' +
          window.location.href +
          '&spirit_animal=scorpion'

        $auth.authenticate('github', {params: {spirit_animal: 'scorpion'}})
        assert $window.open.calledWith(expectedAuthUrl)

    suite 'defaults config', ->
      setup ->
        dfd = $auth.authenticate('github')

        return false


      suite 'postMessage success', ->
        test 'user should be authenticated', (done)->
          called = false
          dfd.then(=>
            called = true
          )

          # fake response from api redirect
          $window.postMessage({
            message:    "deliverCredentials"
            id:         validUser.id
            uid:        validUser.uid
            email:      validUser.email
            auth_token: validToken
            expiry:     validExpiry
            client_id:  validClient
          }, '*')

          setTimeout((->
            $timeout.flush()

            assert.deepEqual($rootScope.user, {
              id:         validUser.id
              uid:        validUser.uid
              email:      validUser.email
              auth_token: validToken
              expiry:     validExpiry
              client_id:  validClient
              signedIn:   true
            })

            assert(true, called)

            done()
          ))

        test 'promise is resolved', ->
          dfd.then(-> assert(true))
          $timeout.flush()

      suite 'directive access', ->
        args = 'github'

        setup ->
          sinon.spy($auth, 'authenticate')
          $rootScope.authenticate('github')
          $timeout.flush()

        test '$auth.authenticate was called from $rootScope', ->
          assert $auth.authenticate.calledWithMatch(args)


      suite 'postMessage error', (done) ->
        errorResponse =
          message: 'authFailure'
          errors: ['420']

        setup ->
          sinon.spy($auth, 'cancel')

        test 'error response cancels authentication', (done) ->
          called = false

          dfd.finally(->
            called = true
          )

          # fake response from api redirect
          $window.postMessage(errorResponse, '*')

          setTimeout((->
            $timeout.flush()
            assert true, called
            assert $auth.cancel.called
            assert $rootScope.$broadcast.calledWith('auth:login-error')
            done()
          ), 0)

        test 'promise is rejected', ->
          dfd.catch(-> assert(true))
          $timeout.flush()


      suite 'postMessage window closed before message is sent', ->
        setup ->
          sinon.spy($auth, 'cancel')

        teardown ->
          popupWindow.closed = false

        test 'auth is cancelled', (done) ->
          called = false

          dfd.catch =>
            called = true

          popupWindow.closed = true

          $timeout.flush()

          assert $auth.cancel.called
          assert.equal(true, called)
          assert.equal(null, $auth.t)
          done()

        test 'promise is rejected', ->
          dfd.catch(-> assert(true))
          $timeout.flush()


      suite 'cancel method', ->
        test 'timer is rejected then nullified', (done) ->
          called = false

          $auth.t.catch =>
            called = true

          $auth.cancel()

          # wait for reflow
          setTimeout((->
            $timeout.flush()
            assert.equal(true, called)
            assert.equal(null, $auth.t)
            done()
          ), 0)

        test 'promise is rejected then nullified', (done) ->
          called = false

          $auth.dfd.promise.catch ->
            called = true

          $auth.cancel()

          # wait for reflow
          setTimeout((->
            $timeout.flush()
            assert.equal(true, called)
            assert.equal(null, $auth.dfd)
            done()
          ), 0)

  suite 'using hard redirect', ->
    successResp =
      success: true
      data: validUser

    suite 'to api', ->
      redirectUrl = null

      setup ->
        redirectUrl = $auth.buildAuthUrl('github')
        $authProvider.configure({forceHardRedirect: true})

        # mock location replace, create spy
        sinon.stub($auth, 'visitUrl').returns(null)

        $auth.authenticate('github')
        return false

      teardown ->
        $authProvider.configure({forceHardRedirect: false})

      test 'location should be replaced', ->
        assert($auth.visitUrl.calledWithMatch(redirectUrl))

    suite 'on return from api', ->
      setup ->
        $httpBackend
          .expectGET('/api/auth/validate_token')
          .respond(201, successResp)

        setValidAuthQS()

        $auth.validateUser()
        $httpBackend.flush()

      test 'new user is not defined in the root scope', ->
        assert.equal(validUser.uid, $rootScope.user.uid)

      test '$rootScope broadcast validation success event', ->
        assert $rootScope.$broadcast.calledWithMatch('auth:validation-success', validUser)
