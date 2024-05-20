import { BadRequestException, Injectable } from '@nestjs/common';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { PrismaService } from '../../../prisma/prisma.service';
import { LoginDto, RegisterDto } from './dto/user.dto';
import { Response } from 'express';
import * as bcrypt from 'bcrypt'

interface UserData {
  name: string;
  email: string;
  password: string;
  phone_number: number;
}

@Injectable()
export class UsersService {
 constructor(
  private readonly jwtService: JwtService,
  private readonly prisma: PrismaService,
  private readonly configService: ConfigService,
 ) {}

 async register(registerDto: RegisterDto, response: Response){
  const { name, email, password, phone_number } = registerDto;
  const isEmailExist = await this.prisma.user.findUnique({
    where: {
      email,
    },
  });

  if(isEmailExist){
    throw new BadRequestException("Email ya existe");
  }

  const phoneNumbersToCheck = [phone_number];

  const usersWithPhoneNumber = await this.prisma.user.findMany({
    where: {
      phone_number: {
        not: null,
        in: phoneNumbersToCheck,
      },
    },
  });

  if (usersWithPhoneNumber.length > 0) {
    throw new BadRequestException(
      'User already exist with this phone number!',
    );
  }

  const hashedPassword = await bcrypt.hash(password, 10);

  const user = {
      name,
      email,
      password: hashedPassword,
      phone_number,
    };
  
  const activationToken = await this.createActivationToken(user);

  const activationCode = activationToken.activationCode;

  console.log(activationCode);

  return {user, response};
 }

 async createActivationToken(user:UserData) {
  const activationCode = Math.floor(1000 + Math.random() * 9000).toString();

  const token = this.jwtService.sign(
    {
      user,
      activationCode,
    },
    {
      secret: this.configService.get<string>('ACTIVATION_SECRET'),
      expiresIn: '5m',
    }
  );
  return {token, activationCode};
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
