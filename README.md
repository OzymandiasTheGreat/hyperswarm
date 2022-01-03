# Testing

## Hyperbeam

Start hyperbeam on your computer and copy-paste address to `packages/mobile/App.tsx`.
Then in another terminal run `yarn mobile:start` and in yet another terminal
`yarn mobile:(android|ios)`.

ios is untested and possibly broken as I have no Apple devices to test.


## Tape tests

Tests won't run if hyperbeam is connected, not sure why. Just start the app
and pick which tests to run. Currently they all hang.
