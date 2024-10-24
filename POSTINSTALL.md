<!-- 
This file provides your users an overview of how to use your extension after they've installed it. All content is optional, but this is the recommended format. Your users will see the contents of this file in the Firebase console after they install the extension.

Include instructions for using the extension and any important functional details. Also include **detailed descriptions** for any additional post-installation setup required by the user.

Reference values for the extension instance using the ${param:PARAMETER_NAME} or ${function:VARIABLE_NAME} syntax.
Learn more in the docs: https://firebase.google.com/docs/extensions/publishers/user-documentation#reference-in-postinstall

Learn more about writing a POSTINSTALL.md file in the docs:
https://firebase.google.com/docs/extensions/publishers/user-documentation#writing-postinstall
-->

# See it in action

To use this extension, create a new CustomProvider for App Check:

```js
import { AltchaProviderOptions } from '@altcha/firebase-app-check';

const firebaseConfig = {
  // your usual Firebase config
  appId: '...'
};

const app = initializeApp(firebaseConfig);

const altchaProviderOptions = new AltchaProviderOptions({
  appId: firebaseConfig.appId,
  createAltchaChallengeUrl: 'https://.../ext-altcha-app-check-provider-createAltchaChallenge',
  createAppCheckTokenUrl: 'https://.../ext-altcha-app-check-provider-createAppCheckToken',
});
const provider = new CustomProvider(altchaProviderOptions);

initializeAppCheck(app, { provider });
```

Replace `createAltchaChallengeUrl` and `createAppCheckTokenUrl` with URLs of the functions deployed by the extension.

<!-- We recommend keeping the following section to explain how to monitor extensions with Firebase -->
# Monitoring

As a best practice, you can [monitor the activity](https://firebase.google.com/docs/extensions/manage-installed-extensions#monitor) of your installed extension, including checks on its health, usage, and logs.
