import { TokenApiModel } from './../models/token-api.model';
import { Router } from '@angular/router';
import { NgToastService } from 'ng-angular-popup';
import { AuthService } from './../services/auth.service';
import { Injectable } from '@angular/core';
import {
  HttpRequest,
  HttpHandler,
  HttpEvent,
  HttpInterceptor,
  HttpErrorResponse
} from '@angular/common/http';
import { catchError, Observable, switchMap, throwError } from 'rxjs';

@Injectable()
export class TokenInterceptor implements HttpInterceptor {

  constructor(private auth: AuthService, private toast: NgToastService, private router: Router) {}

  intercept(request: HttpRequest<unknown>, next: HttpHandler): Observable<HttpEvent<unknown>> {
    const myToken = this.auth.getToken();

    if (myToken) {
      request = this.addTokenToRequest(request, myToken);
    }

    return next.handle(request).pipe(
      catchError((err: any) => {
        if (err instanceof HttpErrorResponse) {
          if (err.status === 401) {
            console.log('Não autorizado, Erro na tentativa de renovação do token...');
            return this.handleUnAuthorizedError(request, next);
          }
        }
        return throwError(() => err);
      })
    );
  }

  addTokenToRequest(request: HttpRequest<unknown>, token: string): HttpRequest<unknown> {
    // Clone the original request and add the new token
    const updatedRequest = request.clone({
      setHeaders: { Authorization: `Bearer ${token}` }
    });

    return updatedRequest;
  }

  handleUnAuthorizedError(req: HttpRequest<any>, next: HttpHandler) {
    const tokenApiModel = new TokenApiModel();
    tokenApiModel.accessToken = this.auth.getToken()!;
    tokenApiModel.refreshToken = this.auth.getRefreshToken()!;

    return this.auth.renewToken(tokenApiModel)
      .pipe(
        switchMap((data: TokenApiModel) => {
          this.auth.storeRefreshToken(data.refreshToken);
          this.auth.storeToken(data.accessToken);
          const updatedRequest = this.addTokenToRequest(req, data.accessToken);
          return next.handle(updatedRequest);
        }),
        catchError((err) => {
          return throwError(() => {
            this.toast.warning({ detail: "Warning", summary: "Token expirado, faça o login novamente" });
            this.router.navigate(['login']);
          });
        })
      );
  }
}
