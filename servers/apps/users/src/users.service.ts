import { Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../../prisma/prisma.service';
import { LoginDto, RegisterDto } from './dto/user.dto';

@Injectable()
export class UsersService {
 constructor(
  private readonly jwtService: JwtService,
  private readonly prisma: PrismaService,
  private readonly configService: ConfigService,
 ) {}

 async register(registerDto: RegisterDto){
  const {name,email,password} = registerDto;
  const user = {
    name,
    email,
    password
  };
  return user;
 }

 async Login(loginDto: LoginDto) {
  const { email, password } = loginDto;
  const user = {
    email,
    password,
  };
  return user;
 }

 async getUsers(){
  return this.prisma.user.findMany({});
 }


}