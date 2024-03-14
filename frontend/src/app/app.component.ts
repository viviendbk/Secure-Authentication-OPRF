import { Component } from '@angular/core';
import { UserService } from './services/user.service';
@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  signUpEmail: string = '';
  signUpPassword: string = '';
  signInEmail: string = '';
  signInPassword: string = '';
  accountCreated: boolean = false;
  signInSuccess: boolean = false;
  signInError: boolean = false;

  constructor(private userService: UserService) { }

  onSignUp(): void {
    console.log('Signing up...');
    console.log('Email:', this.signUpEmail);
    console.log('Password:', this.signUpPassword);
    // Generate key pairs (DSA)
    if (this.signUpEmail && this.signUpPassword) {
      this.accountCreated = true;
      this.userService.createUser(this.signUpEmail, this.signUpPassword)
        .subscribe((response: any) => {
          console.log('Response:', response);
        });
    }
    this.signUpEmail = '';
    this.signUpPassword = '';
  }

  onSignIn(): void {
    console.log('Signing in...');
    console.log('Email:', this.signInEmail);
    console.log('Password:', this.signInPassword);

    setTimeout(() => {
      this.userService.checkUser(this.signInEmail, this.signInPassword)
        .subscribe((response: any) => {
          if (response.message === "Valid user") {
            this.signInSuccess = true;
            this.signInError = false;
          } else {
            this.signInError = true;
            this.signInSuccess = false;
          }
        });
      this.signInEmail = '';
      this.signInPassword = '';
      this.accountCreated = false;
    }, 100);
  }
}
